// Package storage provides primitives for interacting with apostille db data
package storage

import (
	"sync"

	notaryStorage "github.com/docker/notary/server/storage"
)

// Username represents a username string
type Username string

// GUN represents a GUN string
type GUN string

// SignerMetaStore wraps a standard MetaStore and adds signing user information
type SignerMetaStore interface {
	notaryStorage.MetaStore
	AddUserAsSigner(user Username, gun GUN)
	RemoveUserAsSigner(user Username, gun GUN)
	IsSigner(user Username, gun GUN) bool
}

// SignerKey used for hashing user/gun pair for map keys
type SignerKey struct {
	user Username
	gun  GUN
}

// MemoryStore extends MemStorage to implement the SignerMetaStore interface
type MemoryStore struct {
	notaryStorage.MemStorage
	lock    sync.Mutex
	signers map[SignerKey]struct{}
}

// NewMemoryStore creates a new MemoryStore with a standard MemStorage and blank signers
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		MemStorage: *notaryStorage.NewMemStorage(),
		signers:    make(map[SignerKey]struct{}),
	}
}

// AddUserAsSigner adds a user to the signing group for a GUN
func (m *MemoryStore) AddUserAsSigner(user Username, gun GUN) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.signers[SignerKey{user, gun}] = struct{}{}
}

// RemoveUserAsSigner removes a user from the signing group for a GUN
func (m *MemoryStore) RemoveUserAsSigner(user Username, gun GUN) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.signers, SignerKey{user, gun})
}

// IsSigner returns whether or not a user is in the group of signers for a GUN
func (m *MemoryStore) IsSigner(user Username, gun GUN) bool {
	_, ok := m.signers[SignerKey{user, gun}]
	return ok
}
