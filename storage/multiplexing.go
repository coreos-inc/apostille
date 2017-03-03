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
	for _, update := range allUpdates {
		logrus.Infof("%s.%d.%s", update.Role, update.Version, update.Channels[0].Name)
	}

	if err := st.MetaStore.UpdateMany(gun, allUpdates); err != nil {
		logrus.Info("Failed to update metadata")
		return err
	}

	return nil
}

//setChannel puts a slice of MetaUpdates into a particular set of channels
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
func (st *MultiplexingStore) mapUpdatesToRoles(updates []notaryStorage.MetaUpdate) (map[data.RoleName]notaryStorage.MetaUpdate, map[data.RoleName]int) {
	oldMetadata := make(map[data.RoleName]notaryStorage.MetaUpdate)
	oldMetadataIdx := map[data.RoleName]int{
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
func (st *MultiplexingStore) swizzleTargets(gun data.GUN, updates []notaryStorage.MetaUpdate) ([]notaryStorage.MetaUpdate, error) {
	repo, err := st.copyAlternateRoot()
	if err != nil {
		return nil, err
	}

	oldMetadata, oldMetadataIdx := st.mapUpdatesToRoles(updates)

	if oldMetadataIdx[data.CanonicalTargetsRole] == -1 {
		logrus.Info("no target changes to swizzle")
		return updates, nil
	}

	if oldMetadataIdx[st.stashedTargetsRole] == -1 {
		logrus.Info("attempting to overwrite stashed signer-rooted targets file")
		return nil, fmt.Errorf("attempting to overwrite reserved delegation: %s", st.stashedTargetsRole)
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
		_, rootData, err := st.MetaStore.GetCurrent(gun, data.CanonicalRootRole)
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
	err = repo.UpdateDelegationKeys(st.stashedTargetsRole, oldTargetKeys, []string{}, 1)
	if err != nil {
		return nil, err
	}
	logrus.Info("delegation created")
	err = repo.UpdateDelegationPaths(st.stashedTargetsRole, []string{""}, []string{}, false)
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
	signedReleases, err := data.TargetsFromSigned(&decodedTargets, st.stashedTargetsRole)
	if err != nil {
		return nil, err
	}
	repo.Targets[st.stashedTargetsRole] = signedReleases

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

	newReleases, err := repo.Targets[st.stashedTargetsRole].MarshalJSON()
	if err != nil {
		return nil, err
	}
	logrus.Info("new releases: ", string(newReleases))
	updates = append(updates, notaryStorage.MetaUpdate{
		Role:    st.stashedTargetsRole,
		Data:    newReleases,
		Version: repo.Targets[st.stashedTargetsRole].Signed.Version,
	})

	return updates, nil
}
