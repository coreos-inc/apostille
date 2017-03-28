package storagetest

import (
	"testing"

	"github.com/coreos-inc/apostille/servertest"
	"github.com/coreos-inc/apostille/storage"
	notaryStorage "github.com/docker/notary/server/storage"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	"github.com/docker/notary/tuf/testutils"
	"github.com/stretchr/testify/require"
)

// MultiplexingMetaStoreMock creates a MultiplexingMetaStore prepped with a Root for metadata to be stored under
func MultiplexingMetaStoreMock(t *testing.T, trust signed.CryptoService) *storage.MultiplexingStore {
	rootGUN := data.GUN("quay")
	rootChannels := []*notaryStorage.Channel{&storage.Root}
	rootRepo := servertest.CreateRepo(t, rootGUN, trust)
	r, tg, sn, ts, err := testutils.Sign(rootRepo)
	require.NoError(t, err)
	rootJson, targetsJson, ssJson, tsJson, err := testutils.Serialize(r, tg, sn, ts)
	require.NoError(t, err)

	rootStore := notaryStorage.NewMemStorage()
	updates := []notaryStorage.MetaUpdate{
		{
			data.CanonicalRootRole,
			1,
			rootJson,
			rootChannels,
		},
		{
			data.CanonicalSnapshotRole,
			1,
			ssJson,
			rootChannels,
		},
		{
			data.CanonicalTargetsRole,
			1,
			targetsJson,
			rootChannels,
		},
		{
			data.CanonicalTimestampRole,
			1,
			tsJson,
			rootChannels,
		},
	}

	err = rootStore.UpdateMany(rootGUN, updates)
	require.NoError(t, err)
	return storage.NewMultiplexingStore(notaryStorage.NewMemStorage(), rootStore, trust, storage.SignerRoot, storage.AlternateRoot, storage.Root, rootGUN, "targets/releases")
}
