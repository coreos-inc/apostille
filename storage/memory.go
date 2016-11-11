package storage

import notaryStorage "github.com/docker/notary/server/storage"

type Username string
type GUN string

type SignerMetaStore interface {
	notaryStorage.MetaStore
	AddUserAsSigner(user Username, gun GUN) error
	RemoveUserAsSigner(user Username, gun GUN) error
	IsSigner(user Username, gun GUN) bool
}

type SignerKey struct {
	user Username
	gun  GUN
}

type MemoryStore struct {
	notaryStorage.MemStorage
	signers map[SignerKey]struct{}
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		MemStorage: *notaryStorage.NewMemStorage(),
		signers:    make(map[SignerKey]struct{}),
	}
}

func (m *MemoryStore) AddUserAsSigner(user Username, gun GUN) error {
	m.signers[SignerKey{user, gun}] = struct{}{}
	return nil
}

func (m *MemoryStore) RemoveUserAsSigner(user Username, gun GUN) error {
	delete(m.signers, SignerKey{user, gun})
	return nil
}

func (m *MemoryStore) IsSigner(user Username, gun GUN) bool {
	_, ok := m.signers[SignerKey{user, gun}]
	return ok
}
