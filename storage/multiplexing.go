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

// SignerRoot is the channel under which all signer (user) rooted metadata lives
// It is aliased to `Published` right now so that we don't have to intercept the rest
// of the notary server API (e.g. key rotation) which needs to fetch the canonical versions of timestamp/snapshot
var SignerRoot = notaryStorage.Published

// AlternateRoot is the channel under which alternate (quay) rooted metadata lives
var AlternateRoot = notaryStorage.Channel{
	ID:   3,
	Name: "alternate-rooted",
}

// Root is the root repo that alternate-rooted metadata gets rooted under
var Root = notaryStorage.Channel{
	ID:   4,
	Name: "quay",
}

// MultiplexingStore implements the MetaStore interface, splitting metadata between two roots
type MultiplexingStore struct {
	notaryStorage.MetaStore
	SignerChannelMetaStore    notaryStorage.MetaStore
	AlternateChannelMetaStore notaryStorage.MetaStore
	cryptoService             signed.CryptoService
	rootRepo                  tuf.Repo
	stashedTargetsRole        data.RoleName
	defaultChannel            notaryStorage.Channel
	alternateRootChannel      notaryStorage.Channel
}

// NewMultiplexingStore composes a new Multiplexing store instance from underlying stores.
func NewMultiplexingStore(store notaryStorage.MetaStore, cs signed.CryptoService, rootRepo tuf.Repo, defaultChannel notaryStorage.Channel, alternateRootChannel notaryStorage.Channel, stashedTargetsRole data.RoleName) *MultiplexingStore {
	return &MultiplexingStore{
		MetaStore:                 store,
		SignerChannelMetaStore:    NewChannelMetastore(store, defaultChannel),
		AlternateChannelMetaStore: NewChannelMetastore(store, alternateRootChannel),
		cryptoService:             cs,
		rootRepo:                  rootRepo,
		stashedTargetsRole:        stashedTargetsRole,
		defaultChannel:            defaultChannel,
		alternateRootChannel:      alternateRootChannel,
	}
}

// UpdateMany updates multiple TUF records at once
// This updates both the quay root and the signer root
func (st *MultiplexingStore) UpdateMany(gun data.GUN, updates []notaryStorage.MetaUpdate) error {
	allUpdates := make([]notaryStorage.MetaUpdate, 0, len(updates)*2)
	allUpdates = append(allUpdates, st.setChannels(updates, &st.defaultChannel)...)
	for _, update := range updates {
		logrus.Info(update.Role)
	}
	alternateRootUpdates, err := st.swizzleTargets(gun, updates)
	if err != nil {
		logrus.Info("Unable to swizzle targets")
		return err
	}

	alternateRootUpdates = st.setChannels(alternateRootUpdates, &st.alternateRootChannel)
	allUpdates = append(allUpdates, alternateRootUpdates...)

	if err := st.MetaStore.UpdateMany(gun, allUpdates); err != nil {
		logrus.Info("Failed to update metadata")
		return err
	}

	return nil
}

// swizzleTargets modifies the updates so that correct targets and delegations are created in the alternate root store
func (st *MultiplexingStore) swizzleTargets(gun data.GUN, updates []notaryStorage.MetaUpdate) ([]notaryStorage.MetaUpdate, error) {
	logrus.Debug("swizzling targets role for update")

	repo, err := st.copyAlternateRoot()
	if err != nil {
		return nil, err
	}

	signerRootedMetadata, signerRootedMetadataIdx := st.mapUpdatesToRoles(updates)

	if !st.shouldSwizzle(signerRootedMetadataIdx) {
		logrus.Debug("no target changes to swizzle")
		return updates, nil
	}

	if !st.swizzleAllowed(signerRootedMetadataIdx) {
		return nil, fmt.Errorf("attempting to overwrite reserved delegation: %s", st.stashedTargetsRole)
	}

	signerRootedTargetKeys, err := st.getSignerRootedTargetKeys(gun, signerRootedMetadata, signerRootedMetadataIdx)
	if err != nil {
		return nil, err
	}

	err = st.stashSignerRootedTargetsRole(repo, signerRootedTargetKeys, signerRootedMetadata)
	if err != nil {
		return nil, err
	}

	updates, err = st.modifyUpdates(updates, repo, signerRootedMetadata, signerRootedMetadataIdx)
	if err != nil {
		return nil, err
	}
	return updates, nil
}

//setChannels puts a slice of MetaUpdates into a particular set of channels
func (st *MultiplexingStore) setChannels(updates []notaryStorage.MetaUpdate, channels ...*notaryStorage.Channel) []notaryStorage.MetaUpdate {
	channelUpdates := make([]notaryStorage.MetaUpdate, len(updates))
	for i, update := range updates {
		update.Channels = channels
		channelUpdates[i] = update
	}
	return channelUpdates
}

// copyAlternateRoot makes a copy of the global repo, so per-repo changes don't affect it
func (st *MultiplexingStore) copyAlternateRoot() (*tuf.Repo, error) {
	repo := tuf.NewRepo(st.cryptoService)
	repo.Root = st.rootRepo.Root
	logrus.Debug("Copying global repo")
	if _, err := repo.InitTargets(data.CanonicalTargetsRole); err != nil {
		return nil, err
	}
	logrus.Debug("Targets initialized")
	if err := repo.InitSnapshot(); err != nil {
		return nil, err
	}
	logrus.Debug("Snapshot initialized")
	if err := repo.InitTimestamp(); err != nil {
		return nil, err
	}
	logrus.Debug("Timestamp initialized")
	return repo, nil
}

// mapUpdatesToRoles puts updates into maps accessible by name, instead of a list
func (st *MultiplexingStore) mapUpdatesToRoles(updates []notaryStorage.MetaUpdate) (map[data.RoleName]notaryStorage.MetaUpdate, map[data.RoleName]int) {
	metadata := make(map[data.RoleName]notaryStorage.MetaUpdate)
	metadataIdx := map[data.RoleName]int{
		data.CanonicalRootRole:      -1,
		data.CanonicalSnapshotRole:  -1,
		data.CanonicalTargetsRole:   -1,
		data.CanonicalTimestampRole: -1,
	}
	for i, u := range updates {
		for _, role := range data.BaseRoles {
			if u.Role == role {
				metadata[role] = u
				metadataIdx[role] = i
			}
		}
	}
	return metadata, metadataIdx
}

// shouldSwizzle decides whether the set of updates requires swizzling
func (st *MultiplexingStore) shouldSwizzle(oldMetadataIdx map[data.RoleName]int) bool {
	// only swizzle updates if there have been changes to the targets role
	return oldMetadataIdx[data.CanonicalTargetsRole] != -1
}

// swizzleAllowed determines if the set of updates is swizzl-able
func (st *MultiplexingStore) swizzleAllowed(oldMetadataIdx map[data.RoleName]int) bool {
	// we don't allow swizzling if the update includes the `stashedTargetsRole`, since that's what apostille
	// uses to re-root
	return oldMetadataIdx[st.stashedTargetsRole] != -1
}

// getSignerRootedTargetKeys gets the target keys from the signer-rooted metadata that need to be stashed in stashedTargetsRole
func (st *MultiplexingStore) getSignerRootedTargetKeys(gun data.GUN, signerRootedMetadata map[data.RoleName]notaryStorage.MetaUpdate, signerRootedMetadataIdx map[data.RoleName]int) (data.KeyList, error) {
	// fetch target keys from root - these will be pushed down to StashedTargetsRole
	// and replaced with the global target keys
	var signerTargetKeys data.KeyList
	var decodedRoot data.SignedRoot
	var rootBytes []byte
	if signerRootedMetadataIdx[data.CanonicalRootRole] > -1 {
		rootBytes = signerRootedMetadata[data.CanonicalRootRole].Data
	} else {
		logrus.Debug("root not included in updates, loading last stored root")
		_, rootData, err := st.MetaStore.GetCurrent(gun, data.CanonicalRootRole)
		if err != nil || rootData == nil {
			return nil, fmt.Errorf("no root available to fetch target role from")
		}
		rootBytes = rootData
	}

	err := json.Unmarshal(rootBytes, &decodedRoot)
	if err != nil {
		return nil, err
	}
	baseTargetsRole, err := decodedRoot.BuildBaseRole(data.CanonicalTargetsRole)
	if err != nil {
		return nil, err
	}
	for _, key := range baseTargetsRole.Keys {
		signerTargetKeys = append(signerTargetKeys, key)
		logrus.Info("found key ", key)
	}
	return signerTargetKeys, nil
}

// stashSignerRootedTargetsRole takes the signer-rooted targets role and moves it down to StashedTargetsRole
func (st *MultiplexingStore) stashSignerRootedTargetsRole(repo *tuf.Repo, signerRootedTargetKeys data.KeyList, signerRootedMetadata map[data.RoleName]notaryStorage.MetaUpdate) error {
	// add a StashedTargetsRole delegations that contains the keys from targets
	// this is adding the delegation to the 'targets' metadata
	err := repo.UpdateDelegationKeys(st.stashedTargetsRole, signerRootedTargetKeys, []string{}, 1)
	if err != nil {
		return err
	}
	logrus.Info("delegation created")
	err = repo.UpdateDelegationPaths(st.stashedTargetsRole, []string{""}, []string{}, false)
	logrus.Info("delegation paths updated")
	if err != nil {
		return err
	}

	// copy the original targets file as-is over to 'StashedTargetsRole'
	var decodedTargets data.Signed
	err = json.Unmarshal(signerRootedMetadata[data.CanonicalTargetsRole].Data, &decodedTargets)
	if err != nil {
		return err
	}
	signedReleases, err := data.TargetsFromSigned(&decodedTargets, st.stashedTargetsRole)
	if err != nil {
		return err
	}
	repo.Targets[st.stashedTargetsRole] = signedReleases

	// resign targets, snapshot, and timestamp - the signer has all of these keys
	if _, err = repo.SignTargets(data.CanonicalTargetsRole, data.DefaultExpires(data.CanonicalTimestampRole)); err != nil {
		return err
	}
	if _, err = repo.SignSnapshot(data.DefaultExpires(data.CanonicalSnapshotRole)); err != nil {
		return err
	}
	if _, err = repo.SignTimestamp(data.DefaultExpires(data.CanonicalTimestampRole)); err != nil {
		return err
	}
	return nil
}

// modifyUpdates takes a modified repo (post-swizzling) and propagates those changes into the updates array
func (st *MultiplexingStore) modifyUpdates(updates []notaryStorage.MetaUpdate, repo *tuf.Repo, signerRootedMetadata map[data.RoleName]notaryStorage.MetaUpdate, signerRootedMetadataIdx map[data.RoleName]int) ([]notaryStorage.MetaUpdate, error) {
	if signerRootedMetadataIdx[data.CanonicalRootRole] > -1 {
		newRoot, err := repo.Root.MarshalJSON()
		if err != nil {
			return nil, err
		}
		updates[signerRootedMetadataIdx[data.CanonicalRootRole]].Data = newRoot
	}

	if signerRootedMetadataIdx[data.CanonicalSnapshotRole] > -1 {
		newSS, err := repo.Snapshot.MarshalJSON()
		if err != nil {
			return nil, err
		}
		updates[signerRootedMetadataIdx[data.CanonicalSnapshotRole]].Data = newSS
	}

	newTargets, err := repo.Targets[data.CanonicalTargetsRole].MarshalJSON()
	if err != nil {
		return nil, err
	}
	updates[signerRootedMetadataIdx[data.CanonicalTargetsRole]].Data = newTargets

	newTS, err := repo.Timestamp.MarshalJSON()
	if err != nil {
		return nil, err
	}
	updates[signerRootedMetadataIdx[data.CanonicalTimestampRole]].Data = newTS

	newReleases, err := repo.Targets[st.stashedTargetsRole].MarshalJSON()
	if err != nil {
		return nil, err
	}
	updates = append(updates, notaryStorage.MetaUpdate{
		Role:    st.stashedTargetsRole,
		Data:    newReleases,
		Version: repo.Targets[st.stashedTargetsRole].Signed.Version,
	})
	return updates, nil
}
