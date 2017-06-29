#!/usr/bin/env bash

set -e

export GIT_SHA=$(git rev-parse --short --verify HEAD)

docker build -f server.Dockerfile -t quay.io/quay/apostille:${GIT_SHA} .
docker build -f signer.Dockerfile -t quay.io/quay/apostille-signer:${GIT_SHA} .

docker push quay.io/quay/apostille:${GIT_SHA}
docker push quay.io/quay/apostille-signer:${GIT_SHA}