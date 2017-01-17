package storage

// SignerStore stores signer data in some backend
type SignerStore interface {
	AddUserAsSigner(user Username, gun GUN) error
	RemoveUserAsSigner(user Username, gun GUN) error
	IsSigner(user Username, gun GUN) bool
}

