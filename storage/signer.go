package storage

import "github.com/docker/notary/tuf/data"

// SignerStore stores signer data in some backend
type SignerStore interface {
	AddUserAsSigner(user Username, gun data.GUN) error
	RemoveUserAsSigner(user Username, gun data.GUN) error
	IsSigner(user Username, gun data.GUN) bool
}
