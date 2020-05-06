"""
Fetches stuff from the Alexa List based on Selenium

Micah Sherr <msherr@cs.georgetown.edu>
"""

import traceback
import smtplib
from email.message import EmailMessage
from functools import partial
from datetime import datetime
import re
from scapy.all import wrpcap
from scapy.all import AsyncSniffer
from pyvirtualdisplay import Display
from timeit import default_timer as timer
import multiprocessing_logging
from multiprocessing import Process, Value
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.wait import WebDriverWait
import argparse
import gzip
import csv
import logging
import time
import signal
import numpy
import os
from stem.control import Controller
from stem.process import launch_tor_with_config
from stem import CircStatus
from tbselenium.tbdriver import TorBrowserDriver
import tbselenium.common as cm
from tbselenium.utils import launch_tbb_tor_with_stem, prepend_to_env_var
from selenium.webdriver.common.utils import free_port
import tempfile
from os.path import join, dirname



PT_TRANSPORTS = {
    'obfs4' : '/usr/bin/obfs4proxy',
    'obfs5' : '/usr/bin/obfs5proxy',
    'meek'  : '/usr/bin/meek-client',
}

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-c', '--capture',
        dest="do_pcaps",
        help="capture pcap files",
        action='store_true',
        default=False
        )
    parser.add_argument(
        '-f',
        dest="alexafile",
        help="input Alexa file",
        required=True
        )
    parser.add_argument(
        '-l', '--log',
        dest='output',
        required=True,
        help='where to write the log output (in addition to stdout)'
        )
    parser.add_argument(
        '-e', '--email',
        dest='email',
        required=True,
        help='email address to which crash reports should be sent'
        )
    parser.add_argument(
        '-a', '--alexaworkers',
        dest='alexaworkers',
        type=int,
        default=10,
        help='number of Alexa-visitor workers'
        )
    parser.add_argument(
        '-t', '--tor',
        dest='torworkers',
        type=int,
        default=1,
        help='number of tor workers'
        )
    parser.add_argument(
        '-T', '--tbb',
        dest='torbrowser',
        default='/tor/tor-browser_en-US/',
        help='path to Tor browser (e.g., /path/to/tbb/tor-browser_en-US/)'
        )
    parser.add_argument(
        '-j', '--bridges',
        dest='bridge_descriptors',
        help='text file containing newline-deliminted list of bridge descriptors'
        )
    parser.add_argument(
        '-d', '--delay',
        dest='maxdelay',
        type=float,
        default=5,
        help='max delay between requests for a given worker'
        )
    parser.add_argument(
        '-p', '--resetprob',
        dest='resetprob',
        type=float,
        default=1.0,
        help='probability that Tor/Bridge browser resets itself after doing a GET'
        )
    parser.add_argument(
        '-s', '--snaplen',
        dest='snaplen',
        type=int,
        default=0,
        help='snaplen for tcpdump (0 = use tcpdump\'s default'
        )
    
    args = parser.parse_args()
    return args



def read_alexa_list( filename ):
    logger = logging.getLogger('fetcher.py')
    logger.info( 'reading alexa list from %s' % filename )
    urls = []
    with gzip.open(filename,'rt') as f:
        csvreader = csv.reader(f)
        for line in csvreader:
            url = 'http://%s' % line[1]
            urls.append(url)
    return urls


"""
sample according to the Zipf distribution, using an arbitrarilyy 
chosen distribution parameter.
"""
def sample_from_urls( urls ):
    a = 1.2
    r = None
    while r is None or r > len(urls):
        r = numpy.random.zipf(a)
    r -= 1
    return urls[r]


"""
actually perform the fetches
"""
def do_fetches( worker_name, driver, urls, args, time_check, reset_prob = None ):
    logger = logging.getLogger('fetcher.py')

    driver.set_page_load_timeout(60)
    driver.implicitly_wait(60)
    
    while True:
        
        driver.delete_all_cookies()
        url = sample_from_urls(urls)
        logger.info( '[%s] will fetch %s' % (worker_name,url) )

        try:
            start = timer()
            driver.get(url)
            end = timer()
            logger.info( '[%s] fetched %s in %f seconds' % (worker_name,url,(end-start)) )
        except Exception as e:
            logger.warn( '[%s] failed to fetch %s; ==> %s' % (worker_name,url,e) )
        finally:
            time_check.value = time.time()
            delay_time = numpy.random.random_sample() * args.maxdelay
            time.sleep(delay_time)

        if reset_prob is not None:
            if numpy.random.random() <= reset_prob:
                logger.info( '[%s] stopping fetching' % worker_name )
                return
        


"""
worker "process" that visits sites via Firefox
"""
def direct_worker( args, urls, worker_name, time_check ):
    logger = logging.getLogger('fetcher.py')    
    numpy.random.seed()

    logger.info( '[%s] starting display' % worker_name )
    display = Display(visible=0, size=(1024, 768))
    display.start() 
    
    profile = webdriver.FirefoxProfile()
    profile.set_preference("browser.cache.disk.enable", False)
    profile.set_preference("browser.cache.memory.enable", False)
    profile.set_preference("browser.cache.offline.enable", False)
    profile.set_preference("network.http.use-cache", False)
    driver = webdriver.Firefox( profile )
    wait = WebDriverWait(driver, timeout=10)

    do_fetches( worker_name, driver, urls, args, time_check )

    # never really gets here, but this seems like good form
    driver.close()



"""
worker "process" that visits sites via Tor
if specified, bridge_line uses a bridge (it should exclude the "Bridge" prefix)
"""
def tor_worker( args, urls, worker_name, bridge_type, bridge_line, time_check ):
    global tor_processes
    logger = logging.getLogger('fetcher.py')    
    numpy.random.seed()

    logger.info( '[%s] starting display' % worker_name )
    display = Display(visible=0, size=(1024, 768))
    display.start() 

    if bridge_type is not None: 
        transport_exec = PT_TRANSPORTS[bridge_type]
        
    preferences = {
        "browser.cache.memory.enable" : False,
        "browser.cache.offline.enable" : False,
        "network.http.use-cache" : False
    }
    
    # this outer loop is necessary since the browser might reset itself
    while True:
        socks_port = free_port()
        control_port = free_port()
        tor_data_dir = tempfile.mkdtemp()
        tor_binary = join(args.torbrowser, cm.DEFAULT_TOR_BINARY_PATH)
        logger.info("[%s] using SOCKS port: %s, Control port: %s" % (worker_name, socks_port, control_port))
        torrc = {
            'ControlPort'   : str(control_port),
            'SOCKSPort'     : str(socks_port),
            'DataDirectory' : tor_data_dir,
            'HiddenServiceStatistics': '0',
            'DirReqStatistics' : '0',
            'Log'           : 'notice file %s/tor.log' % tor_data_dir,
        }
        if bridge_type is not None:
            preferences['extensions.torlauncher.default_bridge_type'] = bridge_type
            for i in range(1,15):
                pref_string = 'extensions.torlauncher.default_bridge.%s.%d' % (bridge_type,i)
                preferences[pref_string] = bridge_line
            torrc['Bridge']     = bridge_line
            torrc['UseBridges'] = '1'
            torrc['ClientTransportPlugin'] = '%s exec %s' % (bridge_type,transport_exec)
        logging.info( '[%s] preferences = %s' % (worker_name, preferences) )
        logging.info( '[%s] torrc = %s' % (worker_name, torrc) )        

        launched_Tor = False
        while launched_Tor is False:
            try:
                prepend_to_env_var("LD_LIBRARY_PATH", dirname(tor_binary))
                tor_process = launch_tor_with_config(config=torrc, tor_cmd=tor_binary, timeout=300)
                #tor_process = launch_tbb_tor_with_stem(tbb_path=args.torbrowser, torrc=torrc,
                #                                       tor_binary=tor_binary)
                launched_Tor = True
            except OSError as e:
                logging.warn( '[%s] Failed to invoke Tor: %s' % (worker_name, e) )
                time.sleep( 60 ) # wait one minute and try again
                
    
        with Controller.from_port(port=control_port) as controller:
            controller.authenticate()
            with TorBrowserDriver(
                    args.torbrowser,
                    default_bridge_type=bridge_type,
                    pref_dict=preferences,
                    socks_port=socks_port,
                    control_port=control_port) as driver:
                # fetch until we are told to "reboot"
                do_fetches( worker_name, driver, urls, args, time_check, args.resetprob )
                logger.info( '[%s] Resetting' % worker_name )
                try:
                    driver.close()
                    time.sleep(4) # wait a few seconds for things to settle
                except Exception as e:
                    logger.warn( '%s Closing driver caused badness: %s' % (worker_name,e) )
                

        # if we get here, then we should kill the Tor process
        tor_process.kill()
        
    return                      # we can't actually get here
    


def ctrl_c_handler(signum, frame):
    global subprocesses

    logger = logging.getLogger('fetcher.py')
    logger.info( 'SIGINT received.  Shutting down' )
    os.system( "killall -q tcpdump" ) # TODO: admittedly, this is dumb
    for p in subprocesses:
        try:
            p.terminate()
            time.sleep(1)
            p.kill()
            logger.info( 'Killed subprocess' )
        except Exception as e:
            logger.warn( e )
    logging.info( 'waiting for things to stop' )
    time.sleep(5)
    exit(0)


    
def read_bridges_file( filename ):
    logger = logging.getLogger('fetcher.py')    
    if filename is None:
        return [],None
    else:
        with open( filename, 'r' ) as f:
            bridge_descriptors = f.read().splitlines() 
            bridge_ips = []
            bridge_types = {}
            for d in bridge_descriptors:
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+", d)
                if m:
                    ip = m.group(1)
                    bridge_ips.append(ip)
                    # TODO: add more bridge types here
                    if 'obfs4' in d: bridge_types[ip] = 'obfs4' 
                    if 'obfs5' in d: bridge_types[ip] = 'obfs5'
                    if 'meek'  in d: bridge_types[ip] = 'meek'
                    if 'fte' in d: bridge_types[ip] = 'fte'
                    if ip not in bridge_types: bridge_types[ip] = 'plain'
                else:
                    logger.warn( 'could not find bridge IP address in "%s"' % d )
            logger.info( 'read bridges: %s' % bridge_descriptors )
            logger.info( 'bridge IPs: %s' % bridge_ips )            
            return bridge_descriptors,bridge_ips,bridge_types



    
"""
launches a bunch of tcpdump instances
"""
def create_pcap_sniffers( bridge_ips, bridge_types, snaplen ):
    logger = logging.getLogger('fetcher.py')
    filename_prefix = "captures/%s-" % datetime.today().strftime('%Y%m%d-%H%M%S')
    logger.info( 'captures will have prefix "%s"' % filename_prefix )
    
    # first, let's figure out the main filter
    main_filter = ""
    for bridge in bridge_ips:
        if main_filter == "":
            main_filter = "not host %s" % bridge
        else:
            main_filter += " and not host %s" % bridge
    filename_main = "%s-nonbridge.pcap" % filename_prefix
    logger.info( 'main pcap filter: "%s"' % main_filter )
    os.system( "tcpdump -s %d -n -w %s %s &" % (snaplen,filename_main,main_filter) )

    # next, create a separate pcap for each bridge
    counter = 0
    for bridge in bridge_ips:
        bridge_filter = "host %s" % bridge
        filename = "%s-bridge_%s@%s.pcap" % (filename_prefix,bridge_types[bridge],bridge)
        os.system( "tcpdump -s %d -n -w %s %s &" % (snaplen,filename,bridge_filter) )        



"""
starts (or restarts) a process and updates the subprocesses datastructure
if old_process isn't None, then it uses the values saved there and restarts it
"""
def start_subprocess( target, name, p_type, args, old_process = None):
    global subprocesses
    
    if old_process is not None:
        target = subprocesses[old_process]['target']
        name = subprocesses[old_process]['name']
        p_type = subprocesses[old_process]['type']
        args = subprocesses[old_process]['args']
        del subprocesses[old_process]
        try:                    # kill it!
            p.terminate()
            time.sleep(1)
            p.kill()
        except Exception:
            pass
    args_without_timecheck = args
    time_check = Value('d',time.time())        
    args = args + (time_check,)
    p = Process(target=target, name=name, args=args)
    subprocesses[p] = {
        'target' : target,
        'args' : args_without_timecheck,
        'name' : name,
        'type' : p_type,
        'last-check' : time_check
    }
    p.start()

    
        
def main( args ):
    global subprocesses

    tor_processes = []
    signal.signal(signal.SIGINT, ctrl_c_handler)

    # set up logging
    FORMAT = '%(asctime)-15s %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        format=FORMAT,
        level=logging.INFO,
        handlers=[
            logging.FileHandler(args.output),
            logging.StreamHandler()]
        )
    multiprocessing_logging.install_mp_handler()
    logger = logging.getLogger('fetcher.py')
    logging.Formatter.converter = time.gmtime   # use GMT

    logger.info( "running with arguments: %s" % args )
    
    urls = read_alexa_list( args.alexafile )
    bridge_descriptors,bridge_ips,bridge_types = read_bridges_file( args.bridge_descriptors )

    # start various pcaps
    if args.do_pcaps:
        create_pcap_sniffers( bridge_ips, bridge_types, args.snaplen )

    subprocesses = {}
    
    # start vanilla (non-Tor) fetchers
    for i in range(args.alexaworkers):
        name = 'Direct-%d' % i
        start_subprocess( direct_worker, name, 'direct', (args,urls,name) )
    # start Tor (non-bridge) fetchers
    for i in range(args.torworkers):
        name = 'Tor-%d' % i
        start_subprocess( tor_worker, name, 'tor', (args,urls,name,None,None) )
    # start bridge workers
    for i in range(len(bridge_ips)):
        bridge_type = bridge_types[bridge_ips[i]]
        bridge_line = bridge_descriptors[i]
        name = 'Bridge-%s-%s' % (bridge_type,i)
        start_subprocess( tor_worker, 
                          name,
                          bridge_type,
                          (args,urls,name,bridge_type,bridge_line) )

    # continuously check the health of each process
    while True:
        for p in subprocesses:
            p_data = subprocesses[p]
            # first, check whether it's alive
            if p.is_alive():
                logger.info( 'process %s is alive' % p.name )
            else:
                logger.warn( 'process %s is NOT alive; restarting it' % p.name )
                # restart it
                start_subprocess( None, None, None, None, p )

            # second, check whether it needs to be updated
            now = time.time()
            then = p_data['last-check'].value
            if now - then > 100: # TODO: increase this at some point
                logger.warn( 'process %s seems to have stalled; restarting it' % p.name )
                start_subprocess( None, None, None, None, p )

        time.sleep(5)




    
if __name__== "__main__":
    args = parse_args()
    
    try:
        main( args )
    except Exception as e:
        tb = traceback.format_exc()
        print( "Something very bad happened:\n%s\n\n%s" % (e,tb) )
        msg = EmailMessage()
        msg.set_content("fetcher.py crashed.  oh no!\n\nIt ran with arguments %s.\n\nHere's what happened:\n%s\n\n\n%s" % (args, e,tb) )
        msg['Subject'] = '[fetcher.py] crash report'
        msg['From'] = 'fetcher'
        msg['To'] = args.email

        # Send the message via our own SMTP server.
        s = smtplib.SMTP('localhost')
        s.send_message(msg)
        s.quit()
