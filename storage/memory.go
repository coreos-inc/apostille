// Package storage provides primitives for interacting with apostille db data
package storage

import (
	notaryStorage "github.com/docker/notary/server/storage"
	"github.com/docker/notary/tuf/signed"
)

// NewAlternateRootMemStorage instantiates an alternately rooted metadata tree in memory
func NewAlternateRootMemStorage(cs signed.CryptoService) *AlternateRootStore {
	return &AlternateRootStore{
		notaryStorage.NewMemStorage(),
		cs,
	}
}

func NewMultiplexingMemoryStore(memStore *notaryStorage.MemStorage, quayRootStore *AlternateRootStore) *MultiplexingStore {
	return &MultiplexingStore{
		signerRootMetaStore:    memStore,
		alternateRootMetaStore: quayRootStore,
		signers:                make(map[SignerKey]struct{}),
	}
}
