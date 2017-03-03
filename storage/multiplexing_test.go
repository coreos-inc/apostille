package storage

import (
	"testing"

	testUtils "github.com/coreos-inc/apostille/test"
	notaryStorage "github.com/docker/notary/server/storage"
	"github.com/stretchr/testify/require"
)

func TestSetChannels(t *testing.T) {
	trust := testUtils.TrustServiceMock(t)
	rootRepo := testUtils.CreateRepo(t, "quay-root", trust)
	metaStore := NewMultiplexingStore(notaryStorage.NewMemStorage(), trust, *rootRepo, SignerRoot, AlternateRoot, "targets/releases")

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
