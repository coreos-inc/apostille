#!/usr/bin/env bash

set -e

docker-compose -f test.mem.yml build
docker-compose -f test.mem.yml run server -c "go test ./cmd/... ./server/... ./storage/..."
