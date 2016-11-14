package storage

import (
	"sync"

	notaryStorage "github.com/docker/notary/server/storage"
)

type Username string
type GUN string

type SignerMetaStore interface {
	notaryStorage.MetaStore
	AddUserAsSigner(user Username, gun GUN)
	RemoveUserAsSigner(user Username, gun GUN)
	IsSigner(user Username, gun GUN) bool
}

type SignerKey struct {
	user Username
	gun  GUN
}

type MemoryStore struct {
	notaryStorage.MemStorage
	lock    sync.Mutex
	signers map[SignerKey]struct{}
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		MemStorage: *notaryStorage.NewMemStorage(),
		signers:    make(map[SignerKey]struct{}),
	}
}

func (m *MemoryStore) AddUserAsSigner(user Username, gun GUN) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.signers[SignerKey{user, gun}] = struct{}{}
}

func (m *MemoryStore) RemoveUserAsSigner(user Username, gun GUN) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.signers, SignerKey{user, gun})
}

func (m *MemoryStore) IsSigner(user Username, gun GUN) bool {
	_, ok := m.signers[SignerKey{user, gun}]
	return ok
}
