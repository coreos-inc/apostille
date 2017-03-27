package storage

import (
	"fmt"
	"time"

	"github.com/docker/notary/tuf/data"

	notaryStorage "github.com/docker/notary/server/storage"
)

// ErrReadOnly is returned when a write operation is attempted against a read only MetaStore
type ErrReadOnly struct{}

// ErrReadOnly is returned when a write operation is attempted against a read only MetaStore
func (err ErrReadOnly) Error() string {
	return fmt.Sprintf("Error updating metadata. MetaStore is read only.")
}

// ReadOnlyStore implements the MetaStore interface
type ReadOnlyStore struct {
	notaryStorage.MetaStore
}

func (st *ReadOnlyStore) UpdateCurrent(gun data.GUN, update notaryStorage.MetaUpdate) error {
	return ErrReadOnly{}
}

func (st *ReadOnlyStore) UpdateMany(gun data.GUN, updates []notaryStorage.MetaUpdate) error {
	return ErrReadOnly{}
}

func (st *ReadOnlyStore) GetCurrent(gun data.GUN, tufRole data.RoleName, channels ...*notaryStorage.Channel) (created *time.Time, data []byte, err error) {
	return st.MetaStore.GetCurrent(gun, tufRole, channels...)
}

func (st *ReadOnlyStore) GetChecksum(gun data.GUN, tufRole data.RoleName, checksum string, channels ...*notaryStorage.Channel) (created *time.Time, data []byte, err error) {
	return st.MetaStore.GetChecksum(gun, tufRole, checksum, channels...)
}

func (st *ReadOnlyStore) GetVersion(gun data.GUN, tufRole data.RoleName, version int, channels ...*notaryStorage.Channel) (created *time.Time, data []byte, err error) {
	return st.MetaStore.GetVersion(gun, tufRole, version, channels...)
}

func (st *ReadOnlyStore) Delete(gun data.GUN) error {
	return ErrReadOnly{}
}

func (st *ReadOnlyStore) GetChanges(changeID string, records int, filterName string) ([]notaryStorage.Change, error) {
	return st.MetaStore.GetChanges(changeID, records, filterName)
}
