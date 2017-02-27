FROM golang:1.7.3

RUN apt-get update && apt-get install -y \
	curl \
	clang \
	libltdl-dev \
	libsqlite3-dev \
	patch \
	tar \
	xz-utils \
	python \
	python-pip \
	--no-install-recommends \
	&& rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash notary

RUN go get github.com/docker/notary/cmd/notary

ENV NOTARYDIR /go/src/github.com/docker/notary

COPY integration/ ${NOTARYDIR}

RUN chmod -R a+rw /go

WORKDIR ${NOTARYDIR}