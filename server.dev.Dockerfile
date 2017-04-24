FROM golang:1.7.3-alpine
MAINTAINER Evan Cordell "cordell.evan@gmail.com"

RUN apk add --update curl git gcc libc-dev ca-certificates && rm -rf /var/cache/apk/*

# Install SQL DB migration tool
RUN curl -L https://github.com/mattes/migrate/releases/download/$version/migrate.linux-amd64.tar.gz | tar xvz && \
    mv migrate.linux-amd64 /usr/local/bin/migrate

ENV APOSTILLE_SRC github.com/coreos-inc/apostille

# Copy the local repo to the expected go path
COPY . /go/src/${APOSTILLE_SRC}

WORKDIR /go/src/${APOSTILLE_SRC}

ENV SERVICE_NAME=apostille
EXPOSE 4443

# Install apostille
RUN go install \
    -ldflags "-w" \
    ${APOSTILLE_SRC}/cmd/apostille && apk del git gcc libc-dev

#ADD fixtures/root-ca.crt /usr/local/share/ca-certificates/root-ca.crt
RUN update-ca-certificates

ENTRYPOINT [ "/bin/sh" ]
CMD [ "apostille -config=fixtures/config.json" ]