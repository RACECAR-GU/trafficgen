MACHINE=machine1

touch $MACHINE.log
docker run --rm -v `pwd`:/code fetcher -l $MACHINE.log -a 0 -t 1 -e msherr@cs.georgetown.edu -p 1 -j bridge-defs/$MACHINE.txt



