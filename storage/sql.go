package storage

import (
	"fmt"
	"time"

	"github.com/Sirupsen/logrus"
	notaryStorage "github.com/docker/notary/server/storage"
	"github.com/docker/notary/tuf/data"
	"github.com/jinzhu/gorm"
)

var SignerTableName = func() string {
	return "signers"
}

// Signers maps a signing user to a gun
type Signer struct {
	gorm.Model
	Gun    string `sql:"type:varchar(255);not null"`
	Signer string `sql:"type:varchar(255);not null"`
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
func NewSignerSQLStorage(gormDB gorm.DB) *SignerSQLStorage {
	return &SignerSQLStorage{
		DB: gormDB,
	}
}

// AddUserAsSigner adds a user to the signing group for a GUN
func (db *SignerSQLStorage) AddUserAsSigner(user Username, gun data.GUN) error {
	if user == "" {
		logrus.Info("not adding user as signer, username empty")
		return nil
	}
	q := db.Create(&Signer{Gun: string(gun), Signer: string(user)})
	return q.Error
}

// RemoveUserAsSigner removes a user from the signing group for a GUN
func (db *SignerSQLStorage) RemoveUserAsSigner(user Username, gun data.GUN) error {
	signer := Signer{Signer: string(user), Gun: string(gun)}
	q := db.Unscoped().Where(&signer).Delete(Signer{})
	return q.Error
}

// IsSigner returns whether or not a user is in the group of signers for a GUN
func (db *SignerSQLStorage) IsSigner(user Username, gun data.GUN) bool {
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
	tufFileTableName    string
	changefeedTableName string
}

// NewSQLStorage is a convenience method to create a NamespacedSQLStorage
func NewNamespacedSQLStorage(sqlStore *notaryStorage.SQLStorage, namespace string) (*NamespacedSQLStorage, error) {
	var tufTableName string
	var changeTableName string
	if namespace != "" {
		tufTableName = fmt.Sprintf("%s_tuf_files", namespace)
		changeTableName = fmt.Sprintf("%s_changefeed", namespace)
	} else {
		tufTableName = "tuf_files"
		changeTableName = "changefeed"
	}
	return &NamespacedSQLStorage{
		SQLStorage:          *sqlStore,
		tufFileTableName:    tufTableName,
		changefeedTableName: changeTableName,
	}, nil
}

// UpdateCurrent updates a single TUF.
func (db *NamespacedSQLStorage) UpdateCurrent(gun data.GUN, update notaryStorage.MetaUpdate) error {
	notaryStorage.TUFFileTableName = db.tufFileTableName
	notaryStorage.ChangefeedTableName = db.changefeedTableName
	return db.SQLStorage.UpdateCurrent(gun, update)
}

// UpdateMany atomically updates many TUF records in a single transaction
func (db *NamespacedSQLStorage) UpdateMany(gun data.GUN, updates []notaryStorage.MetaUpdate) error {
	notaryStorage.TUFFileTableName = db.tufFileTableName
	notaryStorage.ChangefeedTableName = db.changefeedTableName
	return db.SQLStorage.UpdateMany(gun, updates)
}

// GetCurrent gets a specific TUF record
func (db *NamespacedSQLStorage) GetCurrent(gun data.GUN, tufRole data.RoleName) (*time.Time, []byte, error) {
	notaryStorage.TUFFileTableName = db.tufFileTableName
	notaryStorage.ChangefeedTableName = db.changefeedTableName
	return db.SQLStorage.GetCurrent(gun, tufRole)
}

// GetChecksum gets a specific TUF record by its hex checksum
func (db *NamespacedSQLStorage) GetChecksum(gun data.GUN, tufRole data.RoleName, checksum string) (*time.Time, []byte, error) {
	notaryStorage.TUFFileTableName = db.tufFileTableName
	notaryStorage.ChangefeedTableName = db.changefeedTableName
	return db.SQLStorage.GetChecksum(gun, tufRole, checksum)
}

// Delete deletes all the records for a specific GUN - we have to do a hard delete using Unscoped
// otherwise we can't insert for that GUN again
func (db *NamespacedSQLStorage) Delete(gun data.GUN) error {
	notaryStorage.TUFFileTableName = db.tufFileTableName
	notaryStorage.ChangefeedTableName = db.changefeedTableName
	return db.SQLStorage.Delete(gun)
}

// CheckHealth asserts that the <namespace>_tuf_files table is present
func (db *NamespacedSQLStorage) CheckHealth() error {
	notaryStorage.TUFFileTableName = db.tufFileTableName
	notaryStorage.ChangefeedTableName = db.changefeedTableName
	return db.SQLStorage.CheckHealth()
}

// GetChanges returns up to pageSize changes starting from changeID.
func (db *NamespacedSQLStorage) GetChanges(changeID string, records int, filterName string) ([]notaryStorage.Change, error) {
	notaryStorage.TUFFileTableName = db.tufFileTableName
	notaryStorage.ChangefeedTableName = db.changefeedTableName
	return db.SQLStorage.GetChanges(changeID, records, filterName)
}
