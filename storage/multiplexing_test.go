package storage

import (
	"testing"

	testUtils "github.com/coreos-inc/apostille/test"
	notaryStorage "github.com/docker/notary/server/storage"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	"github.com/docker/notary/tuf/testutils"
	"github.com/stretchr/testify/require"
)

// MultiplexingMetaStoreMock creates a MultiplexingMetaStore prepped with a Root for metadata to be stored under
func MultiplexingMetaStoreMock(t *testing.T, trust signed.CryptoService) *MultiplexingStore {
	rootGUN := data.GUN("quay")
	rootChannels := []*notaryStorage.Channel{&Root}

	rootRepo := testUtils.CreateRepo(t, rootGUN, trust)
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

	return NewMultiplexingStore(notaryStorage.NewMemStorage(), rootStore, trust, SignerRoot, AlternateRoot, Root, rootGUN, "targets/releases")
}

func TestSetChannels(t *testing.T) {
	trust := testUtils.TrustServiceMock(t)
	metaStore := MultiplexingMetaStoreMock(t, trust)

	updates := []notaryStorage.MetaUpdate{
		{
			Role:     "testRole",
			Data:     []byte("test"),
			Version:  1,
			Channels: nil,
		},
		{
			Role:     "testRole",
			Data:     []byte("test"),
			Version:  1,
			Channels: []*notaryStorage.Channel{&notaryStorage.Staged},
		},
	}
	modifiedUpdates := metaStore.setChannels(updates, &AlternateRoot)
	require.Equal(t, 2, len(modifiedUpdates))

	for _, update := range modifiedUpdates {
		require.Equal(t, []*notaryStorage.Channel{&AlternateRoot}, update.Channels)
	}
}
