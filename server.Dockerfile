FROM golang:1.13

ENV APOSTILLE_SRC github.com/coreos-inc/apostille
ENV SERVICE_NAME=apostille

COPY . /go/src/${APOSTILLE_SRC}

RUN apt-get update \
    && apt-get install -y gcc libc-dev musl-dev openssl ca-certificates make

RUN set -ex \
	# && go get -tags 'mysql postgres file' github.com/mattes/migrate/cli && mv /go/bin/cli /go/bin/migrate \
    && go get -tags 'postgres' -u github.com/golang-migrate/migrate/cmd/migrate \
	&& mv /go/src/${APOSTILLE_SRC}/migrations /migrations \
	&& mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH" \
	&& cd /go/src/${APOSTILLE_SRC} \
	&& mv ./fixtures / \
	&& mkdir -p /fixtures/notary \
	&& mv ./vendor/github.com/docker/notary/fixtures/* /fixtures/notary/ \
	&& make build \
	\
	&& update-ca-certificates \
	&& mv /go/bin/apostille /usr/local/bin/ \
	&& cd / \
	&& rm -rf /go \
	&& rm -rf /usr/local/go*

EXPOSE 4443 4442

ENTRYPOINT [ "apostille" ]
CMD [ "-config=/fixtures/config.prod.json" ]
