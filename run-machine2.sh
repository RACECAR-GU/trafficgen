MACHINE=machine2

touch $MACHINE.log
docker run --rm -v `pwd`:/code fetcher -l $MACHINE.log -a 1 -t 0 -e msherr@cs.georgetown.edu -p 1 -j bridge-defs/$MACHINE.txt



