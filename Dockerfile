FROM ubuntu:18.04
MAINTAINER Micah Sherr <msherr@cs.georgetown.edu>

WORKDIR /code
RUN apt-get update

RUN apt-get -y install xvfb firefox-geckodriver
RUN apt-get -y install python3-virtualenv
RUN apt-get -y install python3-pip

RUN useradd -ms /bin/bash user
USER user
ADD requirements.txt .

USER root
RUN pip3 install -r requirements.txt
RUN apt-get -y install x11-utils
RUN apt-get -y install wget

# install Tor Browser
USER root
WORKDIR /tor
RUN chown user /tor
USER user
RUN wget https://www.torproject.org/dist/torbrowser/9.0.10/tor-browser-linux64-9.0.10_en-US.tar.xz
RUN tar xvf tor-browser-linux64-9.0.10_en-US.tar.xz

# install alpha version of Tor Browser (necessary for Snowflake)
USER root
WORKDIR /tmp/tor-alpha
RUN chown user /tmp/tor-alpha
USER user
RUN wget https://www.torproject.org/dist/torbrowser/10.0a1/tor-browser-linux64-10.0a1_en-US.tar.xz
RUN tar xvf tor-browser-linux64-10.0a1_en-US.tar.xz
USER root
RUN mv /tmp/tor-alpha /tor-alpha

# install Tor
WORKDIR /tor
USER root
RUN apt-get -y install apt-transport-https curl
ADD tor-sources.list /etc/apt/sources.list.d/
RUN curl https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
RUN gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -
RUN apt-get update
RUN apt-get -y install tor deb.torproject.org-keyring obfs4proxy zip

# get the latest Alexa list
WORKDIR /alexalist
RUN chown user /alexalist
USER user
RUN wget http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
RUN unzip top-1m.csv.zip
RUN gzip top-1m.csv

# set up some permissions for pcap
USER root
RUN apt-get -y install tcpdump libcap2-bin
RUN setcap cap_net_raw=eip /usr/bin/python3.6
RUN setcap cap_net_raw=eip /usr/sbin/tcpdump

RUN DEBIAN_FRONTEND=noninteractive apt-get -y install --assume-yes postfix
RUN apt-get -y install psmisc git

# install golang
WORKDIR /tmp
RUN wget https://dl.google.com/go/go1.13.linux-amd64.tar.gz
RUN tar -xvf go1.13.linux-amd64.tar.gz
RUN mv go /usr/local

# install obfs5
WORKDIR /code
RUN chown user /code
USER user
ENV GOROOT=/usr/local/go
ENV GOPATH=/code/go
ENV PATH="${GOPATH}/bin:${GOROOT}/bin:${PATH}"
ADD --chown=user obfsX/ obfs5/
WORKDIR /code/obfs5
RUN go get -d ./...
RUN go build -o obfs5proxy ./obfs4proxy
USER root
RUN cp obfs5proxy /usr/bin

# install meek
WORKDIR /code
USER user
RUN git clone https://git.torproject.org/pluggable-transports/meek.git
WORKDIR /code/meek/meek-client
RUN go get -d
RUN go build
USER root
RUN cp meek-client /usr/bin

# copy snowflake from Tor alpha; put it somewhere we can easily find it
USER root
RUN cp /tor-alpha/tor-browser_en-US/Browser/TorBrowser/Tor/PluggableTransports/snowflake-client /usr/bin
RUN chmod 755 /usr/bin/snowflake-client

# finally, let's get this thing working
USER user
WORKDIR /code
ADD --chown=user fetcher.py .
ENTRYPOINT ["python3","fetcher.py","-f","/alexalist/top-1m.csv.gz"]

