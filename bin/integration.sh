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
	docker-compose -f ${composeFile} kill
	docker-compose -f ${composeFile} down -v --remove-orphans
}

function cleanupAndExit {
    cleanup
    exit 1
}

trap cleanupAndExit SIGINT SIGTERM

cleanup

docker-compose -f ${composeFile} build
docker-compose -f ${composeFile} up server &
docker-compose -f ${composeFile} run client &

# Wait on client to finish running
wait $!

# Capture exit code of client
exitCode=$?

cleanup

exit $exitCode
