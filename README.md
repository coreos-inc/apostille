# Apostille

Quay's Image Metadata Signature Service

Apostille acts similarly to a [notary server](https://github.com/docker/notary) in order to support clients using Docker
Content Trust. However, Apostille can expose different chains of trust to clients, and supports non-DCT clients with
additional signing features.

# Building

```
git submodule update --init --recursive --remote
rm -rf vendor/github.com/docker/distribution/vendor
rm -rf vendor/github.com/docker/notary/vendor

go build ./cmd/apostille/
./apostille --config=fixtures/config.json
```


# Dependency updates
```bash
vendetta  # install top-level dependencies
# required: see https://github.com/mattfarina/golang-broken-vendor
rm -rf vendor/github.com/docker/distribution/vendor   
rm -rf vendor/github.com/docker/notary/vendor
vendetta  # install dependencies we just deleted
```

## Pointing to a branch

If we need to point to forked packages (but don't want to change the references in code) they can be updated manually

Currently Notary requires grpc v1.0.1-GA. It refers to a fork instead of a branch on the main repo only because there
is no way to submodule reference a tag.

```bash
git config --file=.gitmodules submodule.vendor/github.com/docker/notary.url https://github.com/ecordell/notary
git config --file=.gitmodules submodule.vendor/github.com/docker/notary.branch lib-fixes
git config --file=.gitmodules submodule.vendor/google.golang.org/grpc.url https://github.com/ecordell/grpc-go
git config --file=.gitmodules submodule.vendor/google.golang.org/grpc.branch v1.0.1-GA
git submodule sync
git submodule update --init --recursive --remote
```

# Running tests

Client (notary) integration tests:

```bash
tests/integration.sh mem
tests/integration.sh mysql
tests/integration.sh postgresql
```