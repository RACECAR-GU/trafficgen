# Web Fetcher

This program continuously fetches webpages, using Selenium.

The easiest way to run this is:

* build the Docker image (do this once)
```
docker build -t fetcher .
```

* to get a bash shell, do something like:
```
docker run -it --rm --entrypoint /bin/bash --user root fetcher
```

* to run the thing, do something like:
```
docker run --rm -v `pwd`:/code fetcher -l log.log -a 5 -t 0 -e msherr@cs.georgetown.edu -p 1 -j /dev/null
```

