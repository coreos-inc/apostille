#!/usr/bin/env bash

db="$1"
case ${db} in
  mem*)
    db="mem"
    ;;
  mysql*)
    db="mysql"
    ;;
  postgresql*)
    db="postgresql"
    ;;
  *)
    echo "Usage: $0 (mem|mysql|postgresql)"
    exit 1
    ;;
esac

composeFile="test.${db}.yml"
project=integration

function cleanup {
	docker-compose -p "${project}_${db}" -f ${composeFile} kill
    docker-compose -p "${project}_${db}" -f ${composeFile} down -v --remove-orphans
}

function cleanupAndExit {
    cleanup
    exitCode=$?
    exit $exitCode
}

BUILDOPTS="--force-rm"

set -e
set -x

cleanup

docker-compose -p "${project}_${db}" -f ${composeFile} config
docker-compose -p "${project}_${db}" -f ${composeFile} build ${BUILDOPTS} --pull | tee

trap cleanupAndExit SIGINT SIGTERM EXIT

docker-compose -p "${project}_${db}" -f ${composeFile} up  --abort-on-container-exit
