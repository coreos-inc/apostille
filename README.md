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
make deps
make test-all
```

# Running tests

```bash
make test         # unit tests
make integration
make test-all
```