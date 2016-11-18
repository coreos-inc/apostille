FROM golang:1.7.3-alpine
MAINTAINER Evan Cordell "cordell.evan@gmail.com"

RUN apk add --update git gcc libc-dev ca-certificates && rm -rf /var/cache/apk/*

# Install SQL DB migration tool
RUN go get github.com/mattes/migrate

ENV APOSTILLE_SRC github.com/coreos-inc/apostille

# Copy the local repo to the expected go path
COPY . /go/src/${APOSTILLE_SRC}

WORKDIR /go/src/${APOSTILLE_SRC}

ENV SERVICE_NAME=apostille
EXPOSE 4443

# Install notary-server
RUN go install \
    -ldflags "-w" \
    ${APOSTILLE_SRC}/cmd/apostille && apk del git gcc libc-dev

#ADD fixtures/root-ca.crt /usr/local/share/ca-certificates/root-ca.crt
RUN update-ca-certificates

ENTRYPOINT [ "apostille" ]
CMD [ "-config=fixtures/config.json" ]
