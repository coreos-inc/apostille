#!/bin/bash

set -exv
BASE_IMG="apostille"
APOSTILLE_IMAGE="quay.io/app-sre/${BASE_IMG}"
IMG="${BASE_IMG}:latest"
GIT_HASH=`get rev-parse --short=7 HEAD`

# build and push server
docker build -t ${IMG}:server-${GIT_HASH} -f ./server.Dockerfile .
docker tag ${IMG}:server-${GIT_HASH} ${IMG}:server-latest

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${IMG}" \
    "docker://${IMG}:server-latest"

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${IMG}" \
    "docker://${IMG}:server-${GIT_HASH}"

# build and push signer
docker build -t ${IMG}:signer-${GIT_HASH} -f ./signer.Dockerfile .
docker tag ${IMG}:signer-${GIT_HASH} ${IMG}:signer-latest

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${IMG}" \
    "docker://${IMG}:signer-latest"

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${IMG}" \
    "docker://${IMG}:signer-${GIT_HASH}"
