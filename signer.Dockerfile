FROM golang:1.7.3-alpine

RUN apk add --update curl git openssh-client gcc libc-dev && rm -rf /var/cache/apk/*

RUN go get github.com/ecordell/migrate 
RUN go get github.com/docker/notary/cmd/notary-signer


ENV SERVICE_NAME=notary_signer
ENV NOTARY_SIGNER_DEFAULT_ALIAS="timestamp_1"
ENV NOTARY_SIGNER_TIMESTAMP_1="testpassword"
RUN chmod 0600 /go/src/github.com/docker/notary/fixtures/database/*

ENTRYPOINT [ "/bin/sh" ]
CMD [ "notary-signer", "-config=/go/src/github.com/docker/notary/fixtures/signer-config.json" ]
