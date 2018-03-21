package storage

import (
	"fmt"
	"time"

	"github.com/docker/notary/tuf/data"

	notaryStorage "github.com/docker/notary/server/storage"
)

// ErrWriteOnly is returned when a read operation is attempted against a write only MetaStore
type ErrWriteOnly struct{}

// ErrWriteOnly is returned when a newer version of TUF metadata is already available
func (err ErrWriteOnly) Error() string {
	return fmt.Sprintf("Error updating metadata. MetaStore is write only.")
}

// ReadOnlyStore implements the MetaStore interface
type WriteOnlyStore struct {
	notaryStorage.MetaStore
}

func (st *WriteOnlyStore) UpdateCurrent(gun data.GUN, update notaryStorage.MetaUpdate) error {
	return st.MetaStore.UpdateCurrent(gun, update)
}

func (st *WriteOnlyStore) UpdateMany(gun data.GUN, updates []notaryStorage.MetaUpdate) error {
	return st.MetaStore.UpdateMany(gun, updates)
}

func (st *WriteOnlyStore) GetCurrent(gun data.GUN, tufRole data.RoleName, channels ...*notaryStorage.Channel) (created *time.Time, data []byte, err error) {
	return nil, nil, ErrWriteOnly{}
}

func (st *WriteOnlyStore) GetChecksum(gun data.GUN, tufRole data.RoleName, checksum string, channels ...*notaryStorage.Channel) (created *time.Time, data []byte, err error) {
	return nil, nil, ErrWriteOnly{}
}

func (st *WriteOnlyStore) GetVersion(gun data.GUN, tufRole data.RoleName, version int, channels ...*notaryStorage.Channel) (created *time.Time, data []byte, err error) {
	return nil, nil, ErrWriteOnly{}
}

// Delete is technically a write operation, but for our uses we don't really need to delete when we're writing
func (st *WriteOnlyStore) Delete(gun data.GUN) error {
	return ErrWriteOnly{}
}

func (st *WriteOnlyStore) GetChanges(changeID string, records int, filterName string) ([]notaryStorage.Change, error) {
	return nil, ErrWriteOnly{}
}
