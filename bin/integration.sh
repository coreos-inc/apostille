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
	docker-compose -p "apostille_integration_${db}" -f ${composeFile} logs ${db}
	docker-compose -p "apostille_integration_${db}" -f ${composeFile} logs notary_signer
	docker-compose -p "apostille_integration_${db}" -f ${composeFile} kill
	docker-compose -p "apostille_integration_${db}" -f ${composeFile} down -v --remove-orphans
}

function cleanupAndExit {
	exitCode=$?
    cleanup
    exit $exitCode
}

trap cleanupAndExit SIGINT SIGTERM EXIT

cleanup

docker-compose -p "apostille_integration_${db}" -f ${composeFile} build
docker-compose -p "apostille_integration_${db}" -f ${composeFile} up server &
docker-compose -p "apostille_integration_${db}" -f ${composeFile} run client &

# Wait on client to finish running
wait $!

# Capture exit code of client
cleanupAndExit
