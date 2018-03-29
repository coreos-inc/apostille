FROM golang:1.9.4

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
	python-setuptools \
	--no-install-recommends \
	&& rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash notary \
	&& go get github.com/golang/lint/golint github.com/fzipp/gocyclo github.com/client9/misspell/cmd/misspell github.com/gordonklaus/ineffassign github.com/HewlettPackard/gas
RUN go get github.com/theupdateframework/notary/cmd/notary

ENV NOTARYDIR /go/src/github.com/theupdateframework/notary

COPY integration/ ${NOTARYDIR}

RUN chmod -R a+rw /go

WORKDIR ${NOTARYDIR}
