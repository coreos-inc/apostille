FROM golang:1.13

RUN apt-get update \
    && apt-get install -y openssh-client gcc libc-dev


RUN go get -tags 'postgres' -u github.com/golang-migrate/migrate/cmd/migrate 
RUN go get github.com/theupdateframework/notary/cmd/notary-signer


ENV SERVICE_NAME=notary_signer
ENV NOTARY_SIGNER_DEFAULT_ALIAS="timestamp_1"
ENV NOTARY_SIGNER_TIMESTAMP_1="testpassword"
RUN chmod 0600 /go/src/github.com/theupdateframework/notary/fixtures/database/*

ADD ./migrations/migrate-signer.sh /migrate.sh
ADD ./fixtures/signer-config.postgres.json /signer-config.postgres.json

ENTRYPOINT [ "/bin/sh" ]
CMD [ "notary-signer", "-config=/go/src/github.com/docker/notary/fixtures/signer-config.json" ]
