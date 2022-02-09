# The Traffic Generator / Web Fetcher

Written by [Micah Sherr](https://seclab.cs.georgetown.edu/msherr) <msherr@cs.georgetown.edu>



This program continuously fetches webpages, using Selenium (with either Firefox or the Tor Browser).	

The Traffic Generator itself is released under the MIT open source license.  See LICENSE.txt.  Note that the pluggable transports, Firefox, Tor, etc. may have different open source licenses.



## Compilation / Building

The traffic generator runs inside of Docker.  You need to build the docker image.  If docker isn't installed, install it.  Then make sure that your user has permission to run docker containers.

Also, make sure that you've pulled the two submodules.
```
git submodule init
git submodule update
```

Next, build the docker image via:
```
docker build -t fetcher .
```

Or just run `./build.sh` that issues the above command.



### What the Dockerfile does

Briefly (and incompletely), the Dockerfile does the following (all within the Docker container/image):

* installs Ubuntu with some X11 stuff and some additional tools (wget, curl, tcpdump, etc.)
* fetches the latest stable version of the [Tor Browser Bundle](https://torproject.org).
* fetches and installs Go (version 1.13)
* installs some Tor pluggable transports
  * [obfs5](https://github.com/RACECAR-GU/obfsX)
  * [meek](https://git.torproject.org/pluggable-transports/meek.git)
  * Snowflake
* downloads the [Alexa top popular website list](http://s3.amazonaws.com/alexa-static/top-1m.csv.zip)
* installs the traffic generator (see fetcher.py)



## Important Notes

For the examples below, things won't break if you make the current directory (where trafficgen resides) have group GID 100 ("users" on Ubuntu) and **g+rwx** permissions.

The issue is that the examples below mount the current directory when running the web fetcher.  This means that log files that the web fetcher writes needs to be able to be written to the current directory by the running docker user.



## Running the thing

To get the command-line options, run:
```bash
docker run --name fetcher --rm -v `pwd`:/code fetcher --help
```

This creates a new container (called fetcher) using the image we previously installed (also called fetcher), and calls it with the `--help` option, which in turn spits out the command-line usage.



#### Examples 

Here are some useful command-lines:

* Run just the direct (Alexa) workers (spawn 5 of them)
```
docker run --rm -v `pwd`:/code fetcher -l log.log -a 5 -t 0 -e msherr@cs.georgetown.edu -p 1 -j /dev/null
```

* Run two Tor (w/o bridges) workers
```
docker run --rm -v `pwd`:/code fetcher -l log.log -a 0 -t 2 -e msherr@cs.georgetown.edu -p 0 -j /dev/null
```

* Run a worker for every bridge defined in the file bridge-defs/gu-obfs5.txt
```
docker run --rm -v `pwd`:/code fetcher -l log.log -a 0 -t 0 -e msherr@cs.georgetown.edu -p 0 -j bridge-defs/gu-obfs5.txt
```





## Debugging

When docker is running, type:
```
docker ps
```
to learn the name of the running container.  (I think it's listed in the rightmost column.) If you used the `--name` option, you probably already know the name of the running container.

To run a shell inside of the running container, do:
```
docker exec -it -u root blissful_hertz /bin/bash
```
(replace blissful_hertz with the correct name of your container).



If you look at the fetcher log file (above, it's called log.log), you can find the location of the Tor log file.  For example, consider the following fetcher log line:

```
2020-04-08 01:58:28,888 root - INFO - [Bridge-obfs5-0] torrc = {'ControlPort': '45511', 'SOCKSPort': '43657', 'DataDirectory': '/tmp/tmpswo26xww', 'HiddenServiceStatistics': '0', 'DirReqStatistics': '0', 'Log': 'notice file /tmp/tmpswo26xww/tor.log', 'Bridge': 'obfs4 34.95.33.61:6666 F46116F9B4D288E816546D1F52CB93F88B2DC341 cert=DUgN3s+5x4zJLedfMcrNByzSqc0puUUYz+xJ3PqDNkEJvuZxXIwsxEkBYjNRlj1xBZniQA iat-mode=0', 'UseBridges': '1', 'ClientTransportPlugin': 'obfs4 exec /usr/bin/obfs5proxy'}
```
here, the Tor log is in **/tmp/tmpswo26xww/tor.log**.



You can also "eavesdrop" on the activities on the web fetcher via:

`docker run --rm -it --network=container:beautiful_babbage ubuntu`

substituting the name of the container being used by the running web fetcher for `beautiful_babbage` (see above).

