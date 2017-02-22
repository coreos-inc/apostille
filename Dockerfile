FROM golang:1.7

RUN apt-get update
RUN apt-get install -y --no-install-recommends \
    make \
    apt-transport-https \
    ca-certificates \
    curl \
    lxc \
    iptables

RUN curl -sSL https://get.docker.com/ | sh
ADD ./wrapdocker /usr/local/bin/wrapdocker
RUN chmod +x /usr/local/bin/wrapdocker
RUN curl -L "https://github.com/docker/compose/releases/download/1.11.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
RUN chmod +x /usr/local/bin/docker-compose


ENV APOSTILLE_SRC github.com/coreos-inc/apostille

COPY . /go/src/${APOSTILLE_SRC}
