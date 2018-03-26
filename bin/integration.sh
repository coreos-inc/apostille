#!/usr/bin/env bash

set -e

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

function cleanup {
	docker-compose -p "apostille_integration_${db}" -f ${composeFile} logs client
	docker-compose -p "apostille_integration_${db}" -f ${composeFile} kill
	docker-compose -p "apostille_integration_${db}" -f ${composeFile} down -v --remove-orphans
}

function cleanupAndExit {
	exitCode=$?
    cleanup
    exit $exitCode
}

docker-compose -p "apostille_integration_${db}" -f ${composeFile} config
docker-compose -p "apostille_integration_${db}" -f ${composeFile} build --pull | tee

trap cleanupAndExit SIGINT SIGTERM EXIT

docker-compose -p "apostille_integration_${db}" -f ${composeFile} up --abort-on-container-exit

# Capture exit code of client
cleanupAndExit
