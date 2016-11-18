# Apostille

Quay's Image Metadata Signature Service

Apostille acts similarly to a [notary server](https://github.com/docker/notary) in order to support clients using Docker Content Trust. However, Apostille can expose different chains of trust to clients, and supports non-DCT clients with additional signing features.

# Usage

```bash
glide install
# required: see https://github.com/mattfarina/golang-broken-vendor
rm -rf vendor/github.com/docker/distribution/vendor   
rm -rf vendor/github.com/docker/notary/vendor                                                                
go build ./cmd/apostille/
./apostille --config=fixtures/config.json
```

Note: updating dependencies may require pinning proto/grpc to the versions used in Notary.