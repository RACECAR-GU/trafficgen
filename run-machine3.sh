MACHINE=machine3

touch $MACHINE.log
docker run --shm-size 2g --rm -v `pwd`:/code fetcher -l $MACHINE.log -a 0 -t 0 -e msherr@cs.georgetown.edu -p 1 -j bridge-defs/$MACHINE.txt -o bridge-defs/$MACHINE-pt-proxy.json

