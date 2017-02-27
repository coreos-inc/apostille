// Package storage provides primitives for interacting with apostille db data
package storage

import (
	notaryStorage "github.com/docker/notary/server/storage"
	"github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/signed"
)

// NewAlternateRootMemStorage instantiates an alternately rooted metadata tree in memory
func NewAlternateRootMemStorage(cs signed.CryptoService, repo tuf.Repo, signerStore notaryStorage.MetaStore) *AlternateRootStore {
	return &AlternateRootStore{
		notaryStorage.NewMemStorage(),
		cs,
		repo,
		signerStore,
	}
}
