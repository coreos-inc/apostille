# Apostille

Quay's Image Metadata Signature Service

Apostille acts similarly to a [notary server](https://github.com/docker/notary) in order to support clients using Docker
Content Trust. However, Apostille can expose different chains of trust to clients, and supports non-DCT clients with
additional signing features.

# Building

```bash
make build
```

# Dependency updates

```bash
make update-deps
make test-all
```

# Running tests

```bash
make test         # unit tests
make integration
make test-all
```

# CI/CD

1. Test with `bin/local-ci.sh`
1. Install yaml, helm, cri plugin
1. `kubectl config use-context <cluster>`
1. Initialize and Login to helm as a user with access to apostille-app
1. `bin/build.sh` -> this builds and pushes the *images* to quay.
1. `bin/deploy-to-staging.sh /path/to/quay-policies-encrypted` pushes helm package to quay and deploys it.
1. `bin/deploy-to-prod.sh /path/to/quay-policies-encrypted`


If you get a 409 conflict when running one of the deploy scripts, comment out the `helm registry push` and retry.