package storage

import (
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	notaryStorage "github.com/docker/notary/server/storage"
)

// MultiplexingMetaStore coordinates serving alternate roots from different metastores
// To accomplish this, it stores a set of signing users for each repo
type MultiplexingMetaStore interface {
	notaryStorage.MetaStore
	SignerRootMetaStore() notaryStorage.MetaStore
	AlternateRootMetaStore() notaryStorage.MetaStore
	AddUserAsSigner(user Username, gun GUN)
	RemoveUserAsSigner(user Username, gun GUN)
	IsSigner(user Username, gun GUN) bool
}

// MultiplexingMemoryStore implements the MultiplexingMetaStore interface
type MultiplexingStore struct {
	lock                   sync.Mutex
	signerRootMetaStore    notaryStorage.MetaStore
	alternateRootMetaStore notaryStorage.MetaStore
	signers                map[SignerKey]struct{}
}

func (st *MultiplexingStore) SignerRootMetaStore() notaryStorage.MetaStore {
	return st.signerRootMetaStore
}

func (st *MultiplexingStore) AlternateRootMetaStore() notaryStorage.MetaStore {
	return st.alternateRootMetaStore
}

// AddUserAsSigner adds a user to the signing group for a GUN
func (st *MultiplexingStore) AddUserAsSigner(user Username, gun GUN) {
	st.lock.Lock()
	defer st.lock.Unlock()
	st.signers[SignerKey{user, gun}] = struct{}{}
}

// RemoveUserAsSigner removes a user from the signing group for a GUN
func (st *MultiplexingStore) RemoveUserAsSigner(user Username, gun GUN) {
	st.lock.Lock()
	defer st.lock.Unlock()
	delete(st.signers, SignerKey{user, gun})
}

// IsSigner returns whether or not a user is in the group of signers for a GUN
func (st *MultiplexingStore) IsSigner(user Username, gun GUN) bool {
	_, ok := st.signers[SignerKey{user, gun}]
	return ok
}

// UpdateMany updates multiple TUF records at once
// This updates both the quay root and the signer root
func (st *MultiplexingStore) UpdateMany(gun string, updates []notaryStorage.MetaUpdate) error {
	st.lock.Lock()
	defer st.lock.Unlock()

	logrus.Info("Updating signer-rooted metadata")
	if err := st.signerRootMetaStore.UpdateMany(gun, updates); err != nil {
		logrus.Info("Failed to update signer-rooted metadata")
		return err
	}

	logrus.Info("Updating alternate-rooted metadata")
	if err := st.alternateRootMetaStore.UpdateMany(gun, updates); err != nil {
		logrus.Warning("Failed to update alternate-rooted metadata. Alternate rooted metadata out of sync with main repo.")
		return err
	}
	return nil
}

// Below methods simply proxy to the underlying store

// UpdateCurrent updates the meta data for a specific role
func (st *MultiplexingStore) UpdateCurrent(gun string, update notaryStorage.MetaUpdate) error {
	st.lock.Lock()
	defer st.lock.Unlock()
	return st.signerRootMetaStore.UpdateCurrent(gun, update)
}

// GetCurrent returns the create/update date metadata for a given role, under a GUN.
func (st *MultiplexingStore) GetCurrent(gun, role string) (*time.Time, []byte, error) {
	st.lock.Lock()
	defer st.lock.Unlock()
	return st.signerRootMetaStore.GetCurrent(gun, role)
}

// GetChecksum returns the create/update date and metadata for a given role, under a GUN.
func (st *MultiplexingStore) GetChecksum(gun, role, checksum string) (*time.Time, []byte, error) {
	st.lock.Lock()
	defer st.lock.Unlock()
	return st.signerRootMetaStore.GetChecksum(gun, role, checksum)
}

// Delete deletes all the metadata for a given GUN
func (st *MultiplexingStore) Delete(gun string) error {
	st.lock.Lock()
	defer st.lock.Unlock()
	return st.signerRootMetaStore.Delete(gun)
}

// GetChanges returns a []Change starting from but excluding the record
func (st *MultiplexingStore) GetChanges(changeID string, records int, filterName string) ([]notaryStorage.Change, error) {
	st.lock.Lock()
	defer st.lock.Unlock()
	return st.signerRootMetaStore.GetChanges(changeID, records, filterName)
}
