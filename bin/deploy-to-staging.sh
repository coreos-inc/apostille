#!/usr/bin/env bash

set -e

export GIT_SHA=$(git rev-parse --short --verify HEAD)
export SEMVER=`git tag | sort -r | head -1 | sed 's/v//g'`+${GIT_SHA}


cd helm/apostille-app
yaml w -i Chart.yaml version "${SEMVER}"

helm init --client-only
helm registry push --namespace quay quay.io

helm upgrade  -f $1/tools/cloudconfig/secrets/helm-values/apostille-staging.yaml \
			  --set apostille_image=quay.io/quay/apostille:${GIT_SHA},signer_image=quay.io/quay/apostille-signer:${GIT_SHA} \
			  --install \
			  apostille-staging .

cd ../..