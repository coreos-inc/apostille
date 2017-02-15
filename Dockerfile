FROM golang:1.7

RUN apt-get update
RUN apt-get install -y \
    make 

ENV APOSTILLE_SRC github.com/coreos-inc/apostille

COPY . /go/src/${APOSTILLE_SRC}
