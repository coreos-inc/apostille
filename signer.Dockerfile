FROM golang:1.7.3-alpine

RUN apk add --update curl git openssh-client gcc libc-dev && rm -rf /var/cache/apk/*

# Install SQL DB migration tool
RUN git clone -b v1 https://github.com/mattes/migrate.git /go/src/github.com/mattes/migrate/
RUN go get -u -v github.com/mattes/migrate && \
    go build -tags 'mysql' -o /usr/local/bin/migrate github.com/mattes/migrate
RUN go get github.com/docker/notary/cmd/notary-signer


ENV SERVICE_NAME=notary_signer
ENV NOTARY_SIGNER_DEFAULT_ALIAS="timestamp_1"
ENV NOTARY_SIGNER_TIMESTAMP_1="testpassword"

ENTRYPOINT [ "/bin/sh" ]
CMD [ "apostile", "-config=/go/src/github.com/docker/notary/fixtures/signer-config.json" ]
