package storage

import (
	"encoding/json"
	"fmt"

	"github.com/Sirupsen/logrus"
	notaryStorage "github.com/docker/notary/server/storage"
	"github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
)

const StashedTargetsRole = "targets/releases"

// Username represents a username string
type Username string

// GUN represents a GUN string
type GUN string

// SignerKey used for hashing user/gun pair for map keys
type SignerKey struct {
	user Username
	gun  GUN
}

// AlternateRootStore stores metadata under a different root than is provided by the client
type AlternateRootStore struct {
	notaryStorage.MetaStore
	cryptoService signed.CryptoService
	rootRepo      tuf.Repo
	signerStore   notaryStorage.MetaStore
}

// NewAlternateRootStorage builds an alternate rooted metastore
func NewAlternateRootStorage(cs signed.CryptoService, store notaryStorage.MetaStore, rootRepo tuf.Repo, signerStore notaryStorage.MetaStore) (*AlternateRootStore, error) {
	return &AlternateRootStore{
		store,
		cs,
		rootRepo,
		signerStore,
	}, nil
}

// UpdateMany updates multiple TUF records at once
// Since this roots all changes to the alternate root, we ignore changes to Root/Snapshot/TS here
// and instead update those manually whenever targets data changes
func (st *AlternateRootStore) UpdateMany(gun string, updates []notaryStorage.MetaUpdate) error {
	updates, err := st.swizzleTargets(gun, updates)
	if err != nil {
		return err
	}

	logrus.Info("applying modified updates")

	// Apply updates
	return st.MetaStore.UpdateMany(gun, updates)
}

// copyAlternateRoot makes a copy of the global repo, so per-repo changes don't affect it
func (st *AlternateRootStore) copyAlternateRoot() (*tuf.Repo, error) {
	repo := tuf.NewRepo(st.cryptoService)
	repo.Root = st.rootRepo.Root
	logrus.Info("Copying global repo")
	if _, err := repo.InitTargets(data.CanonicalTargetsRole); err != nil {
		return nil, err
	}
	logrus.Info("Targets initialized")
	if err := repo.InitSnapshot(); err != nil {
		return nil, err
	}
	logrus.Info("Snapshot initialized")
	if err := repo.InitTimestamp(); err != nil {
		return nil, err
	}
	logrus.Info("Timestamp initialized")
	return repo, nil
}

// mapUpdatesToRoles puts updates into maps accessible by name, instead of a list
func (st *AlternateRootStore) mapUpdatesToRoles(updates []notaryStorage.MetaUpdate) (map[string]notaryStorage.MetaUpdate, map[string]int) {
	oldMetadata := make(map[string]notaryStorage.MetaUpdate)
	oldMetadataIdx := map[string]int{
		data.CanonicalRootRole:      -1,
		data.CanonicalSnapshotRole:  -1,
		data.CanonicalTargetsRole:   -1,
		data.CanonicalTimestampRole: -1,
	}
	for i, u := range updates {
		for _, role := range data.BaseRoles {
			if u.Role == role {
				oldMetadata[role] = u
				oldMetadataIdx[role] = i
			}
		}
	}
	return oldMetadata, oldMetadataIdx
}

// swizzleTargets modifies the updates so that correct targets and delegations are created in the alternate root store
func (st *AlternateRootStore) swizzleTargets(gun string, updates []notaryStorage.MetaUpdate) ([]notaryStorage.MetaUpdate, error) {
	repo, err := st.copyAlternateRoot()
	if err != nil {
		return nil, err
	}

	oldMetadata, oldMetadataIdx := st.mapUpdatesToRoles(updates)

	if oldMetadataIdx[data.CanonicalTargetsRole] == -1 {
		logrus.Info("no target changes to swizzle")
		return updates, nil
	}

	if oldMetadataIdx[StashedTargetsRole] == -1 {
		logrus.Info("attempting to overwrite stashed signer-rooted targets file")
		return nil, fmt.Errorf("attempting to overwrite reserved delegation: %s", StashedTargetsRole)
	}

	logrus.Info("swizzling targets role for update")

	// fetch target keys from root - these will be pushed down to StashedTargetsRole
	// and replaced with the global target keys
	var oldTargetKeys data.KeyList
	var decodedRoot data.SignedRoot
	var rootBytes []byte
	if oldMetadataIdx[data.CanonicalRootRole] > -1 {
		rootBytes = oldMetadata[data.CanonicalRootRole].Data
	} else {
		logrus.Info("root not included in updates, loading last stored root")
		_, rootData, err := st.signerStore.GetCurrent(gun, data.CanonicalRootRole)
		if err != nil || rootData == nil {
			return nil, fmt.Errorf("no root available to fetch target role from")
		}
		rootBytes = rootData
	}

	err = json.Unmarshal(rootBytes, &decodedRoot)
	if err != nil {
		return nil, err
	}
	baseTargetsRole, err := decodedRoot.BuildBaseRole(data.CanonicalTargetsRole)
	if err != nil {
		return nil, err
	}
	for _, key := range baseTargetsRole.Keys {
		oldTargetKeys = append(oldTargetKeys, key)
		logrus.Info("found key ", key)
	}

	// add a StashedTargetsRole delegations that contains the keys from targets
	// this is adding the delegation to the 'targets' metadata
	err = repo.UpdateDelegationKeys(StashedTargetsRole, oldTargetKeys, []string{}, 1)
	if err != nil {
		return nil, err
	}
	logrus.Info("delegation created")
	err = repo.UpdateDelegationPaths(StashedTargetsRole, []string{""}, []string{}, false)
	logrus.Info("delegation paths updated")
	if err != nil {
		return nil, err
	}

	// copy the original targets file as-is over to 'StashedTargetsRole'
	var decodedTargets data.Signed
	err = json.Unmarshal(oldMetadata[data.CanonicalTargetsRole].Data, &decodedTargets)
	if err != nil {
		return nil, err
	}
	signedReleases, err := data.TargetsFromSigned(&decodedTargets, StashedTargetsRole)
	if err != nil {
		return nil, err
	}
	repo.Targets[StashedTargetsRole] = signedReleases

	// resign targets, snapshot, and timestamp - the signer has all of these keys
	if _, err = repo.SignTargets(data.CanonicalTargetsRole, data.DefaultExpires(data.CanonicalTimestampRole)); err != nil {
		return nil, err
	}
	if _, err = repo.SignSnapshot(data.DefaultExpires(data.CanonicalSnapshotRole)); err != nil {
		return nil, err
	}
	if _, err = repo.SignTimestamp(data.DefaultExpires(data.CanonicalTimestampRole)); err != nil {
		return nil, err
	}

	// Modify the updates list with our swizzled data
	if oldMetadataIdx[data.CanonicalRootRole] > -1 {
		newRoot, err := repo.Root.MarshalJSON()
		if err != nil {
			return nil, err
		}
		updates[oldMetadataIdx[data.CanonicalRootRole]].Data = newRoot
	}

	if oldMetadataIdx[data.CanonicalSnapshotRole] > -1 {
		newSS, err := repo.Snapshot.MarshalJSON()
		if err != nil {
			return nil, err
		}
		updates[oldMetadataIdx[data.CanonicalSnapshotRole]].Data = newSS
	}

	newTargets, err := repo.Targets[data.CanonicalTargetsRole].MarshalJSON()
	if err != nil {
		return nil, err
	}
	updates[oldMetadataIdx[data.CanonicalTargetsRole]].Data = newTargets

	logrus.Info("new targets: ", string(newTargets))

	newTS, err := repo.Timestamp.MarshalJSON()
	if err != nil {
		return nil, err
	}
	logrus.Info("new ts: ", string(newTS))
	updates[oldMetadataIdx[data.CanonicalTimestampRole]].Data = newTS

	newReleases, err := repo.Targets[StashedTargetsRole].MarshalJSON()
	if err != nil {
		return nil, err
	}
	logrus.Info("new releases: ", string(newReleases))
	updates = append(updates, notaryStorage.MetaUpdate{
		Role:    StashedTargetsRole,
		Data:    newReleases,
		Version: repo.Targets[StashedTargetsRole].Signed.Version,
	})

	return updates, nil
}
