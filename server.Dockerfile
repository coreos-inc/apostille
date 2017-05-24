FROM golang:1.8.1-alpine

ENV APOSTILLE_SRC github.com/coreos-inc/apostille
ENV SERVICE_NAME=apostille

COPY . /go/src/${APOSTILLE_SRC}

RUN set -ex \
	&& apk add --no-cache --virtual .build-deps \
		bash \
		gcc \
		libc-dev \
		musl-dev \
		openssl \
		ca-certificates \
		go \
		git \
		gcc \
        libc-dev \
        ca-certificates \
        make \
        curl \
	\
	&& go get -tags 'mysql postgres file' github.com/mattes/migrate/cli && mv /go/bin/cli /go/bin/migrate \
    && mv /go/src/${APOSTILLE_SRC}/migrations /migrations \
    && mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH" \
	&& cd /go/src/${APOSTILLE_SRC} \
	&& mv ./fixtures / \
	&& mkdir -p /fixtures/notary \
	&& mv ./vendor/github.com/docker/notary/fixtures/* /fixtures/notary/ \
	&& make build \
	\
	&& update-ca-certificates \
	&& apk del .build-deps \
	&& mv /go/bin/apostille /usr/local/bin/ \
	&& cd / \
	&& rm -rf /go \
	&& rm -rf /usr/local/go*

EXPOSE 4443

ENTRYPOINT [ "apostille" ]
CMD [ "-config=/fixtures/config.prod.json" ]
