package storage

import (
	"time"

	notaryStorage "github.com/docker/notary/server/storage"
	"github.com/docker/notary/tuf/data"
)

// ChannelMetastore implements the MetaStore interface, but fixes the namespace
type ChannelMetastore struct {
	notaryStorage.MetaStore
	channel notaryStorage.Channel
}

// NewChannelMetastore configures a ChannelMetastore to only read from a fixed namespace
func NewChannelMetastore(store notaryStorage.MetaStore, channel notaryStorage.Channel) *ChannelMetastore {
	return &ChannelMetastore{
		MetaStore: store,
		channel:   channel,
	}
}

func (st *ChannelMetastore) GetCurrent(gun data.GUN, tufRole data.RoleName, channels ...*notaryStorage.Channel) (*time.Time, []byte, error) {
	return st.MetaStore.GetCurrent(gun, tufRole, &st.channel)
}

func (st *ChannelMetastore) GetChecksum(gun data.GUN, tufRole data.RoleName, checksum string, channels ...*notaryStorage.Channel) (*time.Time, []byte, error) {
	return st.MetaStore.GetChecksum(gun, tufRole, checksum, &st.channel)
}

func (st *ChannelMetastore) GetVersion(gun data.GUN, tufRole data.RoleName, version int, channels ...*notaryStorage.Channel) (*time.Time, []byte, error) {
	return st.MetaStore.GetVersion(gun, tufRole, version, &st.channel)
}
