# Web Fetcher

This program continuously fetches webpages, using Selenium.

## Compilation / Building

You need to build the docker image.  If docker isn't installed, install it.  Then make sure that your user has permission to run docker containers.

Next, build the docker image via:
```
docker build -t fetcher .
```

## Running the thing

To get the command-line options, run:
```
docker run --rm -v `pwd`:/code fetcher --help
```

Here are some useful command-lines:

* Run just the direct (Alexa) workers (spawn 5 of them)
```
docker run --rm -v `pwd`:/code fetcher -l log.log -a 5 -t 0 -e msherr@cs.georgetown.edu -p 0 -j /dev/null
```

* Run two Tor (w/o bridges) workers
```
docker run --rm -v `pwd`:/code fetcher -l log.log -a 0 -t 2 -e msherr@cs.georgetown.edu -p 0 -j /dev/null
```

* Run a worker for every bridge defined in the file bridges/gu-obfs5.txt
```
docker run --rm -v `pwd`:/code fetcher -l log.log -a 0 -t 0 -e msherr@cs.georgetown.edu -p 0 -j bridges/gu-obfs5.txt
```


## Debugging

When docker is running, type:
```
docker ps
```
to learn the name of the running container.  (I think it's listed in the rightmost column.)

To run a shell inside of the running container, do:
```
docker exec -it -u root blissful_hertz /bin/bash
```
(replace blissful_hertz with the correct name of your container)

If you look at the fetcher log file (above, it's called log.log), you can find the location of the Tor log file.  For example, consider the following fetcher log line:

```
2020-04-08 01:58:28,888 root - INFO - [Bridge-obfs5-0] torrc = {'ControlPort': '45511', 'SOCKSPort': '43657', 'DataDirectory': '/tmp/tmpswo26xww', 'HiddenServiceStatistics': '0', 'DirReqStatistics': '0', 'Log': 'notice file /tmp/tmpswo26xww/tor.log', 'Bridge': 'obfs4 34.95.33.61:6666 F46116F9B4D288E816546D1F52CB93F88B2DC341 cert=DUgN3s+5x4zJLedfMcrNByzSqc0puUUYz+xJ3PqDNkEJvuZxXIwsxEkBYjNRlj1xBZniQA iat-mode=0', 'UseBridges': '1', 'ClientTransportPlugin': 'obfs4 exec /usr/bin/obfs5proxy'}
```
here, the Tor log is in **/tmp/tmpswo26xww/tor.log**.
