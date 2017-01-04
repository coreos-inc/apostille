package storage

import (
	"github.com/Sirupsen/logrus"
	notaryStorage "github.com/docker/notary/server/storage"
	"github.com/docker/notary/trustpinning"
	"github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
)

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
}

// UpdateMany updates multiple TUF records at once
// Since this roots all changes to the alternate root, we ignore changes to Root/Snapshot/TS here
// and instead update those manually whenever targets data changes
func (st *AlternateRootStore) UpdateMany(gun string, updates []notaryStorage.MetaUpdate) error {
	repoBuilder := tuf.NewRepoBuilder(gun, st.cryptoService, trustpinning.TrustPinConfig{})
	var repo *tuf.Repo

	// Attempt to load root roles
	_, currentRoot, err := st.GetCurrent(gun, data.CanonicalRootRole)
	logrus.Info("Checking for existing repo - error loading root: ", err)
	_, currentSnapshot, err := st.GetCurrent(gun, data.CanonicalSnapshotRole)
	logrus.Info("Checking for existing repo - error loading snapshot: ", err)
	_, currentTargets, err := st.GetCurrent(gun, data.CanonicalTargetsRole)
	logrus.Info("Checking for existing repo - error loading targets: ", err)

	// repo exists, load current root roles into temporary tuf repo
	if err == nil {
		repoBuilder.Load(data.CanonicalRootRole, currentRoot, -1, false)
		repoBuilder.Load(data.CanonicalSnapshotRole, currentSnapshot, -1, false)
		repoBuilder.Load(data.CanonicalTargetsRole, currentTargets, -1, false)
		repo, _, err = repoBuilder.Finish()
		if err != nil {
			return err
		}
	} else {
		// bootstrap a new repo (no root exists)
		rootKey, err := st.cryptoService.Create(data.CanonicalRootRole, gun, data.ED25519Key)
		if err != nil {
			return err
		}
		snapshotKey, err := st.cryptoService.Create(data.CanonicalSnapshotRole, gun, data.ED25519Key)
		if err != nil {
			return err
		}
		targetsKey, err := st.cryptoService.Create(data.CanonicalTargetsRole, gun, data.ED25519Key)
		if err != nil {
			return err
		}
		timestampKey, err := st.cryptoService.Create(data.CanonicalTimestampRole, gun, data.ED25519Key)
		if err != nil {
			return err
		}

		rootRole := data.NewBaseRole(
			data.CanonicalRootRole,
			1,
			rootKey,
		)
		targetsRole := data.NewBaseRole(
			data.CanonicalTargetsRole,
			1,
			targetsKey,
		)
		snapshotRole := data.NewBaseRole(
			data.CanonicalSnapshotRole,
			1,
			snapshotKey,
		)
		timestampRole := data.NewBaseRole(
			data.CanonicalTimestampRole,
			1,
			timestampKey,
		)

		repo = tuf.NewRepo(st.cryptoService)
		err = repo.InitRoot(rootRole, timestampRole, snapshotRole, targetsRole, false)
		if err != nil {
			return err
		}

		_, err = repo.InitTargets(data.CanonicalTargetsRole)
		if err != nil {
			return err
		}

		err = repo.InitSnapshot()
		if err != nil {
			return err
		}

		err = repo.InitTimestamp()
		if err != nil {
			return err
		}

		return nil
	}

	// Generate alternate root files as needed
	for _, u := range updates {
		if u.Role == data.CanonicalRootRole {
			// if the target keys have changed, we want to propagate that to the alternate root
			rootLoaderRepoBuilder := tuf.NewBuilderFromRepo(gun, repo, trustpinning.TrustPinConfig{})
			rootLoaderRepoBuilder.Load(data.CanonicalRootRole, u.Data, -1, false)
			tempRepo, _, err := rootLoaderRepoBuilder.Finish()
			if err != nil {
				return err
			}
			repo.Root.Signed.Roles[data.CanonicalTargetsRole] = tempRepo.Root.Signed.Roles[data.CanonicalTargetsRole]
			u.Data, err = repo.Root.MarshalJSON()
			if err != nil {
				return err
			}
		}
		if u.Role == data.CanonicalTargetsRole {
			// if the targets file has changed, we want to load it into the alternate repo
			targetsLoaderRepoBuilder := tuf.NewBuilderFromRepo(gun, repo, trustpinning.TrustPinConfig{})
			targetsLoaderRepoBuilder.Load(data.CanonicalTargetsRole, u.Data, -1, false)
			repo, _, err = targetsLoaderRepoBuilder.Finish()
			if err != nil {
				return err
			}
			u.Data, err = repo.Targets[data.CanonicalTargetsRole].MarshalJSON()
			if err != nil {
				return err
			}
		}
	}

	// Apply updates
	return st.MetaStore.UpdateMany(gun, updates)
}
