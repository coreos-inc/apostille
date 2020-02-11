#!/bin/bash

set -exv
BASE_SERVER_IMG="apostille-server"
BASE_SIGNER_IMG="apostille-signer"
APOSTILLE_SERVER_IMAGE="quay.io/app-sre/${BASE_SERVER_IMG}"
APOSTILLE_SIGNER_IMAGE="quay.io/app-sre/${BASE_SIGNER_IMG}"
GIT_HASH=`git rev-parse --short=7 HEAD`

# build and push server
docker build -t ${APOSTILLE_SERVER_IMG}:${GIT_HASH} -f ./server.Dockerfile .
docker tag ${APOSTILLE_SERVER_IMG}:${GIT_HASH} ${APOSTILLE_SERVER_IMG}:latest

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${APOSTILLE_SERVER_IMG}" \
    "docker://${APOSTILLE_SERVER_IMG}:latest"

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${IMG}" \
    "docker://${APOSTILLE_SERVER_IMG}:${GIT_HASH}"

# build and push signer
docker build -t ${APOSTILLE_SIGNER_IMAGE}:${GIT_HASH} -f ./signer.Dockerfile .
docker tag ${APOSTILLE_SIGNER_IMAGE}:${GIT_HASH} ${APOSTILLE_SIGNER_IMAGE}:latest

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${APOSTILLE_SIGNER_IMAGE}" \
    "docker://${APOSTILLE_SIGNER_IMAGE}:latest"

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${APOSTILLE_SIGNER_IMAGE}" \
    "docker://${APOSTILLE_SIGNER_IMAGE}:${GIT_HASH}"
