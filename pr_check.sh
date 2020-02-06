#!/bin/bash

set -exv

apostille_src='github.com/coreos-inc/apostille'

# run tests in docker container
docker run --rm --name apostille-test-runner -v $(pwd):/go/src/github.com/coreos-inc/apostille golang:latest bash -c 'cd /go/src/github.com/coreos-inc/apostille && make test'

# build server
docker build -f ./server.Dockerfile .

# build signer
docker build -f ./signer.Dockerfile .

