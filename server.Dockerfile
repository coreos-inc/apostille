FROM alpine:3.5

ENV GOLANG_VERSION 1.7.5
ENV GOLANG_SRC_URL https://golang.org/dl/go$GOLANG_VERSION.src.tar.gz
ENV GOLANG_SRC_SHA256 4e834513a2079f8cbbd357502cccaac9507fd00a1efe672375798858ff291815
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
ENV APOSTILLE_SRC github.com/coreos-inc/apostille
ENV SERVICE_NAME=apostille

# https://golang.org/issue/14851
COPY ci/prod/no-pic.patch /
# https://golang.org/issue/17847
COPY ci/prod/17847.patch /
COPY ci/prod/go-wrapper /usr/local/bin/
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
	\
	&& export GOROOT_BOOTSTRAP="$(go env GOROOT)" \
	\
	&& wget -q "$GOLANG_SRC_URL" -O golang.tar.gz \
	&& echo "$GOLANG_SRC_SHA256  golang.tar.gz" | sha256sum -c - \
	&& tar -C /usr/local -xzf golang.tar.gz \
	&& rm golang.tar.gz \
	&& cd /usr/local/go/src \
	&& patch -p2 -i /no-pic.patch \
	&& patch -p2 -i /17847.patch \
	&& ./make.bash \
	\
	&& rm -rf /*.patch \
	&& go get github.com/mattes/migrate \
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
