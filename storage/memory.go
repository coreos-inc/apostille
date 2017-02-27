// Package storage provides primitives for interacting with apostille db data
package storage

import (
	"sync"

	notaryStorage "github.com/docker/notary/server/storage"
	"github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/data"
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

// SignerMemoryStore stores a map of Signers to GUNs
type SignerMemoryStore struct {
	lock    sync.Mutex
	signers map[SignerKey]struct{}
}

// NewSignerMemoryStore creates an empty SignerMemoryStore
func NewSignerMemoryStore() *SignerMemoryStore {
	return &SignerMemoryStore{
		signers: make(map[SignerKey]struct{}),
	}
}

// AddUserAsSigner adds a user to the signing group for a GUN
func (st *SignerMemoryStore) AddUserAsSigner(user Username, gun data.GUN) error {
	st.lock.Lock()
	defer st.lock.Unlock()
	st.signers[SignerKey{user, gun}] = struct{}{}
	return nil
}

// RemoveUserAsSigner removes a user from the signing group for a GUN
func (st *SignerMemoryStore) RemoveUserAsSigner(user Username, gun data.GUN) error {
	st.lock.Lock()
	defer st.lock.Unlock()
	delete(st.signers, SignerKey{user, gun})
	return nil
}

// IsSigner returns whether or not a user is in the group of signers for a GUN
func (st *SignerMemoryStore) IsSigner(user Username, gun data.GUN) bool {
	st.lock.Lock()
	defer st.lock.Unlock()
	_, ok := st.signers[SignerKey{user, gun}]
	return ok
}
