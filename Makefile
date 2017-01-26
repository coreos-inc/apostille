# Set an output prefix, which is the local directory if not specified
PREFIX?=$(shell pwd)

# Populate version variables
# Add to compile time flags
APOSTILLE_PKG := github.com/docker/apostille
APOSTILLE_VERSION := $(shell cat APOSTILLE_VERSION)
GITCOMMIT := $(shell git rev-parse --short HEAD)
GITUNTRACKEDCHANGES := $(shell git status --porcelain --untracked-files=no)
ifneq ($(GITUNTRACKEDCHANGES),)
GITCOMMIT := $(GITCOMMIT)-dirty
endif
CTIMEVAR=-X $(APOSTILLE_PKG)/version.GitCommit=$(GITCOMMIT) \
         -X $(APOSTILLE_PKG)/version.ApostilleVersion=$(APOSTILLE_VERSION)
GO_LDFLAGS=-ldflags "-w $(CTIMEVAR)"
GO_LDFLAGS_STATIC=-ldflags "-w $(CTIMEVAR) -extldflags -static"
GOOSES = darwin linux
APOSTILLE_BUILDTAGS ?= pkcs11
APOSTILLEDIR := /go/src/github.com/docker/apostille

GO_VERSION := $(shell go version | grep "1\.[7-9]\(\.[0-9]+\)*\|devel")

# check to make sure we have the right version. development versions of Go are
# not officially supported, but allowed for building
ifeq ($(strip $(GO_VERSION))$(SKIPENVCHECK),)
$(error Bad Go version - please install Go >= 1.7)
endif

GLIDE := $(shell command -v glide -v 2> /dev/null)

ifndef GLIDE
    $(shell curl https://glide.sh/get | sh)
endif

_empty :=
_space := $(empty) $(empty)

PKGS ?= $(shell go list -tags "${APOSTILLE_BUILDTAGS}" ./... | grep -v /vendor/ | tr '\n' ' ')

.PHONY: clean all build test integration integration-postgres

all: clean build test

${PREFIX}/bin/apostille: APOSTILLE_VERSION $(shell find . -type f -name '*.go')
	@echo "+ $@"
	@go build -tags ${APOSTILLE_BUILDTAGS} -o $@ ${GO_LDFLAGS} ./cmd/apostille


update-deps:
	@glide up -v

build:
	@echo "+ $@"
	@go install -tags "${APOSTILLE_BUILDTAGS}" -v ${GO_LDFLAGS} $(PKGS)

clean:
	@echo "+ $@"
	@rm -rf  "${PREFIX}/bin/apostille"

test:
	@echo "+ $@"
	@go test ./cmd/apostille

integration:
	@echo "+ $@"
	test/integration.sh mysql

integration-postgres:
	@echo "+ $@"
	test/integration.sh postgresql

test-all: test integration integration-postgres
