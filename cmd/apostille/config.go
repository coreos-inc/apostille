package main

import (
	"crypto/tls"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/coreos-inc/apostille/server"
	"github.com/coreos-inc/apostille/storage"
	"github.com/docker/distribution/health"
	_ "github.com/docker/distribution/registry/auth/htpasswd"
	_ "github.com/docker/distribution/registry/auth/token"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/docker/notary"
	notaryStorage "github.com/docker/notary/server/storage"
	"github.com/docker/notary/signer/client"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	"github.com/docker/notary/utils"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"

	"encoding/json"

	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/tuf"
	tufUtils "github.com/docker/notary/tuf/utils"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
)

const (
	envPrefix = "APOSTILLE"
)

// getRequiredGunPrevixes returns the required gun prefixes accepted by this server
func getRequiredGunPrefixes(configuration *viper.Viper) ([]string, error) {
	prefixes := configuration.GetStringSlice("repositories.gun_prefixes")
	for _, prefix := range prefixes {
		// Check that GUN prefixes are in the correct format
		p := path.Clean(strings.TrimSpace(prefix))
		if p+"/" != prefix || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "..") {
			return nil, fmt.Errorf("invalid GUN prefix %s", prefix)
		}
	}
	return prefixes, nil
}

// getAddrAndTLSConfig gets the address for the HTTP server, and parses the optional TLS
// configuration for the server - if no TLS configuration is specified,
// TLS is not enabled.
func getAddrAndTLSConfig(configuration *viper.Viper, httpAddrKey string) (string, *tls.Config, error) {
	httpAddr := configuration.GetString(httpAddrKey)
	if httpAddr == "" {
		return "", nil, fmt.Errorf("http listen address required for server")
	}

	tlsConfig, err := utils.ParseServerTLS(configuration, false)
	if err != nil {
		return "", nil, fmt.Errorf(err.Error())
	}
	return httpAddr, tlsConfig, nil
}

// grpcTLS sets up TLS for the GRPC connection to notary-signer
func grpcTLS(configuration *viper.Viper) (*tls.Config, error) {
	rootCA := utils.GetPathRelativeToConfig(configuration, "trust_service.tls_ca_file")
	clientCert := utils.GetPathRelativeToConfig(configuration, "trust_service.tls_client_cert")
	clientKey := utils.GetPathRelativeToConfig(configuration, "trust_service.tls_client_key")

	if clientCert == "" && clientKey != "" || clientCert != "" && clientKey == "" {
		return nil, fmt.Errorf("either pass both client key and cert, or neither")
	}

	tlsConfig, err := tlsconfig.Client(tlsconfig.Options{
		CAFile:   rootCA,
		CertFile: clientCert,
		KeyFile:  clientKey,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"Unable to configure TLS to the trust service: %s", err.Error())
	}
	return tlsConfig, nil
}

// getStore parses the configuration and returns a backing store for the TUF files
// it returns a Multiplexing store, which splits updates between signer-rooted and alternate-rooted
// the Multiplexing store gets references to the underlying stores it interacts with
func getStore(configuration *viper.Viper, trust signed.CryptoService, hRegister healthRegister) (
	notaryStorage.MetaStore, error) {
	var store notaryStorage.MetaStore

	backend := configuration.GetString("storage.backend")
	logrus.Infof("Using %s tuf backend", backend)

	store, err := getBaseStore(configuration, hRegister, backend, "storage", "tuf files")
	if err != nil {
		return nil, err
	}

	rootBackend := configuration.GetString("root_storage.backend")
	logrus.Infof("Using %s root backend", rootBackend)

	rootStore, err := getBaseStore(configuration, hRegister, rootBackend, "root_storage", "root")
	if err != nil {
		return nil, err
	}

	if err := getQuayRoot(configuration, trust, rootStore); err != nil {
		return nil, err
	}

	return storage.NewMultiplexingStore(
			store,
			rootStore,
			trust,
			storage.SignerRoot,
			storage.AlternateRoot,
			storage.Root,
			data.GUN(configuration.GetString("root_storage.rootGUN")),
			"targets/releases"),
		nil
}

// parseSQLStorage tries to parse out Storage from a Viper.  If backend and
// URL are not provided, returns a nil pointer.  Storage is required (if
// a backend is not provided, an error will be returned.)
func parseSQLStorage(configuration *viper.Viper, block string) (*utils.Storage, error) {
	store := utils.Storage{
		Backend: configuration.GetString(block + ".backend"),
		Source:  configuration.GetString(block + ".db_url"),
	}

	switch {
	case store.Backend != notary.MySQLBackend && store.Backend != notary.SQLiteBackend && store.Backend != notary.PostgresBackend:
		return nil, fmt.Errorf(
			"%s is not a supported SQL backend driver",
			store.Backend,
		)
	case store.Source == "":
		return nil, fmt.Errorf(
			"must provide a non-empty database source for %s",
			store.Backend,
		)
	}
	return &store, nil
}

// getBaseStore gets a basic MetaStore connected to the correct SQL backend. It is wrapped with other layers before
// used.
func getBaseStore(configuration *viper.Viper, hRegister healthRegister, backend, storageKey, dbname string) (store notaryStorage.MetaStore, err error) {
	switch backend {
	case notary.MemoryBackend:
		store = notaryStorage.NewMemStorage()
	case notary.MySQLBackend, notary.SQLiteBackend, notary.PostgresBackend:
		storeConfig, err := parseSQLStorage(configuration, storageKey)
		if err != nil {
			return nil, err
		}
		s, err := notaryStorage.NewSQLStorage(storeConfig.Backend, storeConfig.Source)
		if err != nil {
			return nil, fmt.Errorf("Error starting %s driver: %s", backend, err.Error())
		}
		if configuration.GetString("logging.db_logging") == "on" {
			s.DB.LogMode(true)
		}
		store = *notaryStorage.NewTUFMetaStorage(s)
		hRegister(fmt.Sprintf("%s DB operational", dbname), time.Minute, s.CheckHealth)
	default:
		err = fmt.Errorf("%s is not a supported storage backend", backend)
	}
	return
}

type signerFactory func(hostname, port string, tlsConfig *tls.Config) (*client.NotarySigner, error)
type healthRegister func(name string, duration time.Duration, check health.CheckFunc)

// getNotarySigner returns a grpc connection to the notary-signer server
func getNotarySigner(hostname, port string, tlsConfig *tls.Config) (*client.NotarySigner, error) {
	timeout := time.After(15 * time.Second)
	tick := time.Tick(1 * time.Second)
	var err error
	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("timed out trying to contact remote signer %s:%s, %v", hostname, port, err)
		case <-tick:
			logrus.Info("trying to connect to remote signer")
			conn, err := client.NewGRPCConnection(hostname, port, tlsConfig)
			if err == nil {
				return client.NewNotarySigner(conn), nil
			}
		}
	}
}

// getTrustService parses the configuration and determines which trust service and
// key algorithm to return
func getTrustService(configuration *viper.Viper, sFactory signerFactory,
	hRegister healthRegister) (signed.CryptoService, string, error) {

	switch configuration.GetString("trust_service.type") {
	case "local":
		logrus.Info("Using local signing service, which requires ED25519. " +
			"Ignoring all other trust_service parameters, including keyAlgorithm")
		return signed.NewEd25519(), data.ED25519Key, nil

	case "remote":
	// continue with remote configuration below

	default:
		return nil, "", fmt.Errorf(
			`must specify either a "local" or "remote" type for trust_service`)
	}

	keyAlgo := configuration.GetString("trust_service.key_algorithm")
	if keyAlgo != data.ED25519Key && keyAlgo != data.ECDSAKey && keyAlgo != data.RSAKey {
		return nil, "", fmt.Errorf("invalid key algorithm configured: %s", keyAlgo)
	}

	clientTLS, err := grpcTLS(configuration)
	if err != nil {
		return nil, "", err
	}

	logrus.Info("Using remote signing service")

	notarySigner, err := sFactory(
		configuration.GetString("trust_service.hostname"),
		configuration.GetString("trust_service.port"),
		clientTLS,
	)

	if err != nil {
		return nil, "", err
	}

	duration := 10 * time.Second
	hRegister(
		"Trust operational",
		duration,
		func() error {
			err := notarySigner.CheckHealth(duration, notary.HealthCheckOverall)
			if err != nil {
				logrus.Error("Trust not fully operational: ", err.Error())
			}
			return err
		},
	)
	return notarySigner, keyAlgo, nil
}

// getCacheConfig parses the cache configurations for GET-ting current and checksummed metadata,
// returning the configuration for current (non-content-addressed) metadata
// first, then the configuration for consistent (content-addressed) metadata
// second. The configuration consists mainly of the max-age (an integer in seconds,
// just like in the Cache-Control header) for each type of metadata.
// The max-age must be between 0 and 31536000 (one year in seconds, which is
// the recommended maximum time data is cached), else parsing will return an error.
// A max-age of 0 will disable caching for that type of download (consistent or current).
func getCacheConfig(configuration *viper.Viper) (current, consistent utils.CacheControlConfig, err error) {
	cccs := make(map[string]utils.CacheControlConfig)
	currentOpt, consistentOpt := "current_metadata", "consistent_metadata"

	defaults := map[string]int{
		currentOpt:    int(notary.CurrentMetadataCacheMaxAge.Seconds()),
		consistentOpt: int(notary.ConsistentMetadataCacheMaxAge.Seconds()),
	}
	maxMaxAge := int(notary.CacheMaxAgeLimit.Seconds())

	for optionName, seconds := range defaults {
		m := configuration.GetString(fmt.Sprintf("caching.max_age.%s", optionName))
		if m != "" {
			seconds, err = strconv.Atoi(m)
			if err != nil || seconds < 0 || seconds > maxMaxAge {
				return nil, nil, fmt.Errorf(
					"must specify a cache-control max-age between 0 and %v", maxMaxAge)
			}
		}
		cccs[optionName] = utils.NewCacheControlConfig(seconds, optionName == currentOpt)
	}
	current = cccs[currentOpt]
	consistent = cccs[consistentOpt]
	return
}

func getQuayRoot(configuration *viper.Viper, cs signed.CryptoService, store notaryStorage.MetaStore) error {
	shouldGenerate := configuration.GetString("root_storage.root") == "generate"
	if !shouldGenerate {
		return nil
	}
	rootMetaStore := storage.WriteOnlyStore{MetaStore: storage.NewChannelMetastore(store, storage.Root)}

	gun := data.GUN(configuration.GetString("root_storage.rootGUN"))

	logrus.Infof("Generating root repo for %s", gun.String())

	rootPublicKey, err := cs.Create(data.CanonicalRootRole, gun, data.ECDSAKey)
	if err != nil {
		return err
	}
	rootKey, _, err := cs.GetPrivateKey(rootPublicKey.ID())
	if err != nil {
		return err
	}

	// Generate root public key cert
	startTime := time.Now()
	cert, err := cryptoservice.GenerateCertificate(rootKey, gun, startTime, startTime.Add(notary.Year*10))
	if err != nil {
		return err
	}
	x509PublicKey := tufUtils.CertToKey(cert)
	if x509PublicKey == nil {
		return fmt.Errorf("cannot use regenerated certificate: format %v", cert.PublicKeyAlgorithm)
	}

	// Generate root role
	rootRole := data.NewBaseRole(data.CanonicalRootRole, notary.MinThreshold, x509PublicKey)

	// Generate snapshot role
	snapshotKey, err := cs.Create(data.CanonicalSnapshotRole, gun, data.ECDSAKey)
	if err != nil {
		return err
	}
	snapshotRole := data.NewBaseRole(
		data.CanonicalSnapshotRole,
		notary.MinThreshold,
		snapshotKey,
	)

	// Generate targets role
	targetsKey, err := cs.Create(data.CanonicalTargetsRole, gun, data.ECDSAKey)
	if err != nil {
		return err
	}
	targetsRole := data.NewBaseRole(
		data.CanonicalTargetsRole,
		notary.MinThreshold,
		targetsKey,
	)

	// Generate timestamp role
	timestampKey, err := cs.Create(data.CanonicalTimestampRole, gun, data.ECDSAKey)
	if err != nil {
		return err
	}
	timestampRole := data.NewBaseRole(
		data.CanonicalTimestampRole,
		notary.MinThreshold,
		timestampKey,
	)

	// Generate full repo
	repo := tuf.NewRepo(cs)
	err = repo.InitRoot(rootRole, timestampRole, snapshotRole, targetsRole, false)
	if err != nil {
		return err
	}

	if _, err = repo.InitTargets(data.CanonicalTargetsRole); err != nil {
		return err
	}
	if err = repo.InitSnapshot(); err != nil {
		return err
	}
	if err = repo.InitTimestamp(); err != nil {
		return err
	}

	rootSigned, err := repo.SignRoot(data.DefaultExpires(data.CanonicalRootRole), nil)
	if err != nil {
		return err
	}
	targetsSigned, err := repo.SignTargets(data.CanonicalTargetsRole, data.DefaultExpires(data.CanonicalTargetsRole))
	if err != nil {
		return err
	}
	ssSigned, err := repo.SignSnapshot(data.DefaultExpires(data.CanonicalSnapshotRole))
	if err != nil {
		return err
	}
	tsSigned, err := repo.SignTimestamp(data.DefaultExpires(data.CanonicalTimestampRole))
	if err != nil {
		return err
	}

	rootBytes, err := json.Marshal(rootSigned)
	if err != nil {
		return err
	}
	targetsBytes, err := json.Marshal(targetsSigned)
	if err != nil {
		return err
	}
	ssBytes, err := json.Marshal(ssSigned)
	if err != nil {
		return err
	}
	tsBytes, err := json.Marshal(tsSigned)
	if err != nil {
		return err
	}

	updates := []notaryStorage.MetaUpdate{
		{
			Role:     data.CanonicalRootRole,
			Version:  1,
			Data:     rootBytes,
			Channels: []*notaryStorage.Channel{&storage.Root},
		},
		{
			Role:     data.CanonicalTargetsRole,
			Version:  1,
			Data:     targetsBytes,
			Channels: []*notaryStorage.Channel{&storage.Root},
		},
		{
			Role:     data.CanonicalSnapshotRole,
			Version:  1,
			Data:     ssBytes,
			Channels: []*notaryStorage.Channel{&storage.Root},
		},
		{
			Role:     data.CanonicalTimestampRole,
			Version:  1,
			Data:     tsBytes,
			Channels: []*notaryStorage.Channel{&storage.Root},
		},
	}
	return rootMetaStore.UpdateMany(gun, updates)
}

// parseServerConfig parses the config file into a Config struct
func parseServerConfig(configFilePath string) (context.Context, context.Context, server.Config, server.Config, error) {
	config := viper.New()
	utils.SetupViper(config, envPrefix)

	configError := func(err error) (context.Context, context.Context, server.Config, server.Config, error) {
		return nil, nil, server.Config{}, server.Config{}, err
	}

	// parse viper config
	if err := utils.ParseViper(config, configFilePath); err != nil {
		return configError(err)
	}

	ctx := context.Background()
	adminCtx := context.Background()

	// set default error level
	lvl, err := utils.ParseLogLevel(config, logrus.ErrorLevel)
	if err != nil {
		return configError(err)
	}
	logrus.SetLevel(lvl)

	prefixes, err := getRequiredGunPrefixes(config)
	if err != nil {
		return configError(err)
	}

	trust, keyAlgo, err := getTrustService(config, getNotarySigner, health.RegisterPeriodicFunc)
	if err != nil {
		return configError(err)
	}
	ctx = context.WithValue(ctx, notary.CtxKeyKeyAlgo, keyAlgo)

	rootBackend := config.GetString("root_storage.backend")
	logrus.Infof("Using %s admin backend", rootBackend)

	adminStore, err := getBaseStore(config, health.RegisterPeriodicFunc, rootBackend, "root_storage", "admin")
	if err != nil {
		return configError(err)
	}
	adminMetaStore := storage.NewChannelMetastore(adminStore, storage.Root)
	adminCtx = context.WithValue(adminCtx, notary.CtxKeyMetaStore, adminMetaStore)

	store, err := getStore(config, trust, health.RegisterPeriodicFunc)
	if err != nil {
		return configError(err)
	}
	ctx = context.WithValue(ctx, notary.CtxKeyMetaStore, store)

	currentCache, consistentCache, err := getCacheConfig(config)
	if err != nil {
		return configError(err)
	}

	httpAddr, tlsConfig, err := getAddrAndTLSConfig(config, "server.http_addr")
	if err != nil {
		return configError(err)
	}

	adminHTTPAddr, _, err := getAddrAndTLSConfig(config, "server.admin_http_addr")
	if err != nil {
		return configError(err)
	}

	serverConfig := server.Config{
		Addr:                         httpAddr,
		TLSConfig:                    tlsConfig,
		Trust:                        trust,
		AuthMethod:                   config.GetString("auth.type"),
		AuthOpts:                     config.Get("auth.options"),
		RepoPrefixes:                 prefixes,
		CurrentCacheControlConfig:    currentCache,
		ConsistentCacheControlConfig: consistentCache,
		Admin: false,
	}

	adminServerConfig := server.Config{
		Addr:                         adminHTTPAddr,
		TLSConfig:                    tlsConfig,
		Trust:                        trust,
		AuthMethod:                   "admin",
		AuthOpts:                     nil,
		RepoPrefixes:                 nil,
		CurrentCacheControlConfig:    currentCache,
		ConsistentCacheControlConfig: consistentCache,
		Admin: true,
	}
	return ctx, adminCtx, serverConfig, adminServerConfig, nil
}
