FROM golang:1.9.4-alpine

RUN apk add --update curl git openssh-client gcc libc-dev && rm -rf /var/cache/apk/*

RUN go get -tags 'mysql postgres file' github.com/mattes/migrate/cli && mv /go/bin/cli /go/bin/migrate
RUN go get github.com/theupdateframework/notary/cmd/notary-signer


ENV SERVICE_NAME=notary_signer
ENV NOTARY_SIGNER_DEFAULT_ALIAS="timestamp_1"
ENV NOTARY_SIGNER_TIMESTAMP_1="testpassword"
RUN chmod 0600 /go/src/github.com/theupdateframework/notary/fixtures/database/*

ADD ./migrations/migrate-signer.sh /migrate.sh
ADD ./fixtures/signer-config.postgres.json /signer-config.postgres.json

ENTRYPOINT [ "/bin/sh" ]
CMD [ "notary-signer", "-config=/go/src/github.com/docker/notary/fixtures/signer-config.json" ]
