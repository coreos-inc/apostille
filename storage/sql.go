package storage

import (
	notaryStorage "github.com/docker/notary/server/storage"
	"time"
	"fmt"
	"github.com/jinzhu/gorm"
	"github.com/Sirupsen/logrus"
)

var SignerTableName = func() string {
	return "signers"
}

// Signers maps a signing user to a gun
type Signer struct {
	gorm.Model
	Gun     string	  `sql:"type:varchar(255);not null"`
	Signer  string    `sql:"type:varchar(255);not null"`
}

// TableName sets a specific table name for TUFFile
func (g Signer) TableName() string {
	return SignerTableName()
}

// SignerSQLStorage stores signer data in a SQL db
type SignerSQLStorage struct {
	gorm.DB
}

// NewSignerSQLStorage stores signer data in an existing DB
func NewSignerSQLStorage(gormDB gorm.DB) (*SignerSQLStorage) {
	return &SignerSQLStorage{
		DB: gormDB,
	}
}

// AddUserAsSigner adds a user to the signing group for a GUN
func (db *SignerSQLStorage) AddUserAsSigner(user Username, gun GUN) error {
	if user == "" {
		logrus.Info("not adding user as signer, username empty")
		return nil
	}
	q := db.Create(&Signer{Gun: string(gun), Signer: string(user)})
	return q.Error
}

// RemoveUserAsSigner removes a user from the signing group for a GUN
func (db *SignerSQLStorage) RemoveUserAsSigner(user Username, gun GUN) error {
	signer := Signer{Signer: string(user), Gun: string(gun)}
	q := db.Unscoped().Where(&signer).Delete(Signer{})
	return q.Error
}

// IsSigner returns whether or not a user is in the group of signers for a GUN
func (db *SignerSQLStorage) IsSigner(user Username, gun GUN) bool {
	var row Signer
	q := db.Where(&Signer{Gun: string(gun), Signer: string(user)}).Limit(1).First(&row)
	if q.Error != nil {
		logrus.Infof("couldn't find %s as a signer for %s: %v", user, gun, q.Error)
		return false
	}
	return true
}

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

