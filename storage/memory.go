// Package storage provides primitives for interacting with apostille db data
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

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

// key stores a public key and algorithm
type key struct {
	algorithm string
	public    []byte
}

// ver is a version of metadata at a time
type ver struct {
	version      int
	data         []byte
	createupdate time.Time
}

// we want to keep these sorted by version so that it's in increasing version
// order
type verList []ver

func (k verList) Len() int      { return len(k) }
func (k verList) Swap(i, j int) { k[i], k[j] = k[j], k[i] }
func (k verList) Less(i, j int) bool {
	return k[i].version < k[j].version
}

// SignerKey used for hashing user/gun pair for map keys
type SignerKey struct {
	user Username
	gun  GUN
}

// QuayRootMemStorage stores metadata under an alternate Quay-global root
// TODO: make this more generic
type QuayRootMemStorage struct {
	lock          sync.Mutex
	cryptoService signed.CryptoService
	tufMeta       map[string]verList
	keys          map[string]map[string]*key
	checksums     map[string]map[string]ver
}

// NewQuayRootMemStorage instantiates a memStorage instance
func NewQuayRootMemStorage(cs signed.CryptoService) *QuayRootMemStorage {
	return &QuayRootMemStorage{
		cryptoService: cs,
		tufMeta:       make(map[string]verList),
		keys:          make(map[string]map[string]*key),
		checksums:     make(map[string]map[string]ver),
	}
}

// UpdateMany updates multiple TUF records at once
// Since this roots all changes to Quay's roots, we ignore changes to Root/Snapshot/TS here
// and instead update those manually whenever targets data changes
func (st *QuayRootMemStorage) UpdateMany(gun string, updates []notaryStorage.MetaUpdate) error {
	st.lock.Lock()
	defer st.lock.Unlock()

	versioner := make(map[string]map[int]struct{})
	constant := struct{}{}

	// don't allow old versions of metadata
	for _, u := range updates {
		id := entryKey(gun, u.Role)

		// prevent duplicate versions of the same role
		if _, ok := versioner[u.Role][u.Version]; ok {
			return notaryStorage.ErrOldVersion{}
		}
		if _, ok := versioner[u.Role]; !ok {
			versioner[u.Role] = make(map[int]struct{})
		}
		versioner[u.Role][u.Version] = constant

		if space, ok := st.tufMeta[id]; ok {
			for _, v := range space {
				if v.version >= u.Version {
					return notaryStorage.ErrOldVersion{}
				}
			}
		}
	}

	repoBuilder := tuf.NewRepoBuilder(gun, st.cryptoService, trustpinning.TrustPinConfig{})
	var repo *tuf.Repo

	// Attempt to load root roles
	_, currentRoot, err := st.GetCurrent(gun, data.CanonicalRootRole)
	_, currentSnapshot, err := st.GetCurrent(gun, data.CanonicalSnapshotRole)
	_, currentTargets, err := st.GetCurrent(gun, data.CanonicalTargetsRole)

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
		_, err = repo.InitTargets(data.CanonicalTargetsRole)
		err = repo.InitSnapshot()
		err = repo.InitTimestamp()

		if err != nil {
			return err
		}

	}

	targetsKeyChanged := false
	targetsChanged := false

	// Generate alternate root files as needed
	for _, u := range updates {
		// only care about targets (and target key) updates here, other roles have been generated or loaded above
		if u.Role == data.CanonicalSnapshotRole || u.Role == data.CanonicalTimestampRole {
			continue
		}
		if u.Role == data.CanonicalRootRole {
			// if the target keys have changed, we want to propagate that to the alternate root
			targetsKeyChanged = true
			rootLoaderRepoBuilder := tuf.NewBuilderFromRepo(gun, repo, trustpinning.TrustPinConfig{})
			rootLoaderRepoBuilder.Load(data.CanonicalRootRole, u.Data, -1, false)
			tempRepo, _, err := rootLoaderRepoBuilder.Finish()
			if err != nil {
				return err
			}
			repo.Root.Signed.Roles[data.CanonicalTargetsRole] = tempRepo.Root.Signed.Roles[data.CanonicalTargetsRole]
		}
		if u.Role == data.CanonicalTargetsRole {
			// if the targets file has changed, we want to load it into the alternate repo
			targetsChanged = true
			targetsLoaderRepoBuilder := tuf.NewBuilderFromRepo(gun, repo, trustpinning.TrustPinConfig{})
			targetsLoaderRepoBuilder.Load(data.CanonicalTargetsRole, u.Data, -1, false)
			repo, _, err = targetsLoaderRepoBuilder.Finish()
			if err != nil {
				return err
			}
		}
	}

	// Modify the submitted updates so that the update process can continue as normal
	for _, u := range updates {
		if u.Role == data.CanonicalRootRole && targetsKeyChanged {
			u.Data, err = repo.Root.MarshalJSON()
			if err != nil {
				return err
			}
		}
		if u.Role == data.CanonicalTargetsRole && targetsChanged {
			u.Data, err = repo.Targets[data.CanonicalTargetsRole].MarshalJSON()
			if err != nil {
				return err
			}
		}
	}

	// Apply updates
	for _, u := range updates {
		id := entryKey(gun, u.Role)
		version := ver{version: u.Version, data: u.Data, createupdate: time.Now()}
		st.tufMeta[id] = append(st.tufMeta[id], version)
		sort.Sort(st.tufMeta[id]) // ensure that it's sorted
		checksumBytes := sha256.Sum256(u.Data)
		checksum := hex.EncodeToString(checksumBytes[:])

		_, ok := st.checksums[gun]
		if !ok {
			st.checksums[gun] = make(map[string]ver)
		}
		st.checksums[gun][checksum] = version
	}

	return nil
}

func (st *QuayRootMemStorage) UpdateCurrent(gun string, update notaryStorage.MetaUpdate) error {
	return nil
}

// GetCurrent returns the createupdate date metadata for a given role, under a GUN.
func (st *QuayRootMemStorage) GetCurrent(gun, role string) (*time.Time, []byte, error) {
	id := entryKey(gun, role)
	space, ok := st.tufMeta[id]
	if !ok || len(space) == 0 {
		return nil, nil, notaryStorage.ErrNotFound{}
	}
	return &(space[len(space)-1].createupdate), space[len(space)-1].data, nil
}

// GetChecksum returns the createupdate date and metadata for a given role, under a GUN.
func (st *QuayRootMemStorage) GetChecksum(gun, role, checksum string) (*time.Time, []byte, error) {
	st.lock.Lock()
	defer st.lock.Unlock()
	space, ok := st.checksums[gun][checksum]
	if !ok || len(space.data) == 0 {
		return nil, nil, notaryStorage.ErrNotFound{}
	}
	return &(space.createupdate), space.data, nil
}

// Delete deletes all the metadata for a given GUN
func (st *QuayRootMemStorage) Delete(gun string) error {
	st.lock.Lock()
	defer st.lock.Unlock()
	l := len(st.tufMeta)
	for k := range st.tufMeta {
		if strings.HasPrefix(k, gun) {
			delete(st.tufMeta, k)
		}
	}
	if l == len(st.tufMeta) {
		// we didn't delete anything, don't write change.
		return nil
	}
	delete(st.checksums, gun)
	return nil
}

func (st *QuayRootMemStorage) GetChanges(changeID string, records int, filterName string) ([]notaryStorage.Change, error) {
	return nil, nil
}

func entryKey(gun, role string) string {
	return fmt.Sprintf("%s.%s", gun, role)
}

// MultiplexingMetaStore coordinates serving alternate roots from different metastores
// To accomplish this, it stores a set of signing users for each repo
type MultiplexingMetaStore interface {
	notaryStorage.MetaStore
	GetSignerRootMetaStore() notaryStorage.MetaStore
	GetAlternateRootMetaStore() notaryStorage.MetaStore
	AddUserAsSigner(user Username, gun GUN)
	RemoveUserAsSigner(user Username, gun GUN)
	IsSigner(user Username, gun GUN) bool
}

// MultiplexingMemoryStore implements the SignerMetaStore interface
type MultiplexingMemoryStore struct {
	SignerRootMemoryStore    *notaryStorage.MemStorage
	AlternateRootMemoryStore *QuayRootMemStorage
	lock                     sync.Mutex
	signers                  map[SignerKey]struct{}
}

func NewMultiplexingMemoryStore(memStore *notaryStorage.MemStorage, quayRootStore *QuayRootMemStorage) *MultiplexingMemoryStore {
	return &MultiplexingMemoryStore{
		SignerRootMemoryStore:    memStore,
		AlternateRootMemoryStore: quayRootStore,
		signers:                  make(map[SignerKey]struct{}),
	}
}

func (m *MultiplexingMemoryStore) GetSignerRootMetaStore() notaryStorage.MetaStore {
	return m.SignerRootMemoryStore
}

func (m *MultiplexingMemoryStore) GetAlternateRootMetaStore() notaryStorage.MetaStore {
	return m.AlternateRootMemoryStore
}

// AddUserAsSigner adds a user to the signing group for a GUN
func (m *MultiplexingMemoryStore) AddUserAsSigner(user Username, gun GUN) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.signers[SignerKey{user, gun}] = struct{}{}
}

// RemoveUserAsSigner removes a user from the signing group for a GUN
func (m *MultiplexingMemoryStore) RemoveUserAsSigner(user Username, gun GUN) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.signers, SignerKey{user, gun})
}

// IsSigner returns whether or not a user is in the group of signers for a GUN
func (m *MultiplexingMemoryStore) IsSigner(user Username, gun GUN) bool {
	_, ok := m.signers[SignerKey{user, gun}]
	return ok
}

// UpdateMany updates multiple TUF records at once
// This updates both the quay root and the signer root
func (st *MultiplexingMemoryStore) UpdateMany(gun string, updates []notaryStorage.MetaUpdate) error {
	st.lock.Lock()
	defer st.lock.Unlock()

	logrus.Info("Updating signer-rooted metadata")
	if err := st.SignerRootMemoryStore.UpdateMany(gun, updates); err != nil {
		logrus.Info("Failed to update signer-rooted metadata")
		return err
	}

	logrus.Info("Updating alternate-rooted metadata")
	if err := st.AlternateRootMemoryStore.UpdateMany(gun, updates); err != nil {
		logrus.Info("Failed to update alternate-rooted metadata")
		return err
	}
	return nil
}

func (st *MultiplexingMemoryStore) UpdateCurrent(gun string, update notaryStorage.MetaUpdate) error {
	return nil
}

// GetCurrent returns the createupdate date metadata for a given role, under a GUN.
func (st *MultiplexingMemoryStore) GetCurrent(gun, role string) (*time.Time, []byte, error) {
	return st.SignerRootMemoryStore.GetCurrent(gun, role)
}

// GetChecksum returns the createupdate date and metadata for a given role, under a GUN.
func (st *MultiplexingMemoryStore) GetChecksum(gun, role, checksum string) (*time.Time, []byte, error) {
	return st.SignerRootMemoryStore.GetChecksum(gun, role, checksum)
}

// Delete deletes all the metadata for a given GUN
func (st *MultiplexingMemoryStore) Delete(gun string) error {
	return st.SignerRootMemoryStore.Delete(gun)
}

func (st *MultiplexingMemoryStore) GetChanges(changeID string, records int, filterName string) ([]notaryStorage.Change, error) {
	return st.SignerRootMemoryStore.GetChanges(changeID, records, filterName)
}
