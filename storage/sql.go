package storage

import (
	notaryStorage "github.com/docker/notary/server/storage"
	"time"
	"fmt"
)


// NamespacedSQLStorage sets alternate table names and proxies to a standard SQLStorage
// See server/storage/sqldb.go
type NamespacedSQLStorage struct {
	notaryStorage.SQLStorage
	tufFileTableNameFunc func() string
	changefeedTableNameFunc func() string
}

// NewSQLStorage is a convenience method to create a NamespacedSQLStorage
func NewNamespacedSQLStorage(sqlStore *notaryStorage.SQLStorage, namespace string) (*NamespacedSQLStorage, error) {
	return &NamespacedSQLStorage{
		SQLStorage: *sqlStore,
		tufFileTableNameFunc: func() string {
			if namespace != "" {
				return fmt.Sprintf("%s_tuf_files", namespace)
			} else {
				return "tuf_files"
			}
		},
		changefeedTableNameFunc: func() string {
			if namespace != "" {
				return fmt.Sprintf("%s_changefeed", namespace)
			} else {
				return "changefeed"
			}
		},
	}, nil
}

// UpdateCurrent updates a single TUF.
func (db *NamespacedSQLStorage) UpdateCurrent(gun string, update notaryStorage.MetaUpdate) error {
	notaryStorage.TUFFileTableName = db.tufFileTableNameFunc
	notaryStorage.ChangefeedTableName = db.changefeedTableNameFunc
	return db.SQLStorage.UpdateCurrent(gun, update)
}

// UpdateMany atomically updates many TUF records in a single transaction
func (db *NamespacedSQLStorage) UpdateMany(gun string, updates []notaryStorage.MetaUpdate) error {
	notaryStorage.TUFFileTableName = db.tufFileTableNameFunc
	notaryStorage.ChangefeedTableName = db.changefeedTableNameFunc
	return db.SQLStorage.UpdateMany(gun, updates)
}


// GetCurrent gets a specific TUF record
func (db *NamespacedSQLStorage) GetCurrent(gun, tufRole string) (*time.Time, []byte, error) {
	notaryStorage.TUFFileTableName = db.tufFileTableNameFunc
	notaryStorage.ChangefeedTableName = db.changefeedTableNameFunc
	return db.SQLStorage.GetCurrent(gun, tufRole)
}

// GetChecksum gets a specific TUF record by its hex checksum
func (db *NamespacedSQLStorage) GetChecksum(gun, tufRole, checksum string) (*time.Time, []byte, error) {
	notaryStorage.TUFFileTableName = db.tufFileTableNameFunc
	notaryStorage.ChangefeedTableName = db.changefeedTableNameFunc
	return db.SQLStorage.GetChecksum(gun, tufRole, checksum)
}

// Delete deletes all the records for a specific GUN - we have to do a hard delete using Unscoped
// otherwise we can't insert for that GUN again
func (db *NamespacedSQLStorage) Delete(gun string) error {
	notaryStorage.TUFFileTableName = db.tufFileTableNameFunc
	notaryStorage.ChangefeedTableName = db.changefeedTableNameFunc
	return db.SQLStorage.Delete(gun)
}

// CheckHealth asserts that the <namespace>_tuf_files table is present
func (db *NamespacedSQLStorage) CheckHealth() error {
	notaryStorage.TUFFileTableName = db.tufFileTableNameFunc
	notaryStorage.ChangefeedTableName = db.changefeedTableNameFunc
	return db.SQLStorage.CheckHealth()
}

// GetChanges returns up to pageSize changes starting from changeID.
func (db *NamespacedSQLStorage) GetChanges(changeID string, records int, filterName string) ([]notaryStorage.Change, error) {
	notaryStorage.TUFFileTableName = db.tufFileTableNameFunc
	notaryStorage.ChangefeedTableName = db.changefeedTableNameFunc
	return db.SQLStorage.GetChanges(changeID, records, filterName)
}

