#!/usr/bin/env bash

set -e

bin/test.sh
bin/integration.sh mysql
bin/integration.sh postgresql
bin/build.sh