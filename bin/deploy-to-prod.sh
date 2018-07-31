#!/usr/bin/env bash

set -e

export GIT_SHA=$(git rev-parse --short --verify HEAD)
export SEMVER=`git tag | sort -r | head -1 | sed 's/v//g'`+${GIT_SHA}


cd helm/apostille-app
yaml w -i Chart.yaml version "${SEMVER}"

helm template . -f $1/tools/cloudconfig/secrets/helm-values/apostille-prod.yaml > templated.yaml
kubectl apply -f templated.yaml
rm templated.yaml


cd ../..
