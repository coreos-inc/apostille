FROM golang:1.7.3-alpine

RUN apk add --update curl git gcc libc-dev && rm -rf /var/cache/apk/*

# Install SQL DB migration tool
RUN curl -L https://github.com/mattes/migrate/releases/download/$version/migrate.linux-amd64.tar.gz | tar xvz && \
    mv migrate.linux-amd64 /usr/local/bin/migrate
RUN go get github.com/docker/notary/cmd/notary-signer


ENV SERVICE_NAME=notary_signer
ENV NOTARY_SIGNER_DEFAULT_ALIAS="timestamp_1"
ENV NOTARY_SIGNER_TIMESTAMP_1="testpassword"

ENTRYPOINT [ "/bin/sh" ]
CMD [ "apostile", "-config=/go/src/github.com/docker/notary/fixtures/signer-config.json" ]
