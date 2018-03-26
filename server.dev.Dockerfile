FROM golang:1.9.4-alpine
MAINTAINER Evan Cordell "cordell.evan@gmail.com"

RUN apk add --update curl git gcc libc-dev ca-certificates && rm -rf /var/cache/apk/*

RUN go get -tags 'mysql postgres file' github.com/mattes/migrate/cli && mv /go/bin/cli /go/bin/migrate

ENV APOSTILLE_SRC github.com/coreos-inc/apostille

# Copy the local repo to the expected go path
COPY . /go/src/${APOSTILLE_SRC}

WORKDIR /go/src/${APOSTILLE_SRC}

ENV SERVICE_NAME=apostille
EXPOSE 4443 4442

# Install apostille
RUN go install \
    -ldflags "-w" \
    ${APOSTILLE_SRC}/cmd/apostille

#ADD fixtures/root-ca.crt /usr/local/share/ca-certificates/root-ca.crt
RUN update-ca-certificates

ENTRYPOINT [ "/bin/sh" ]
CMD [ "apostille -config=fixtures/config.json" ]
