package storage

// SignerStore stores signer data in some backend
type SignerStore interface {
	AddUserAsSigner(user Username, gun GUN)
	RemoveUserAsSigner(user Username, gun GUN)
	IsSigner(user Username, gun GUN) bool
}

