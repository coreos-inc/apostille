package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"net"

	"github.com/docker/distribution/health"
	"github.com/docker/notary"
	"github.com/docker/notary/cryptoservice"
	pb "github.com/docker/notary/proto"
	"github.com/docker/notary/signer"
	"github.com/docker/notary/signer/api"
	"github.com/docker/notary/signer/client"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	tufUtils "github.com/docker/notary/tuf/utils"
	"github.com/docker/notary/utils"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/surullabs/lint"
	"github.com/surullabs/lint/dupl"
	"github.com/surullabs/lint/gofmt"
	"github.com/surullabs/lint/golint"
	"github.com/surullabs/lint/gosimple"
	"github.com/surullabs/lint/gostaticcheck"
	"github.com/surullabs/lint/govet"
	"google.golang.org/grpc"
	"github.com/coreos-inc/apostille/storage"
)

const (
	Cert = "../../vendor/github.com/docker/notary/fixtures/notary-server.crt"
	Key  = "../../vendor/github.com/docker/notary/fixtures/notary-server.key"
	Root = "../../vendor/github.com/docker/notary/fixtures/root-ca.crt"
)

func TestLint(t *testing.T) {
	custom := lint.Group{
		gofmt.Check{},             // Enforce gofmt usage
		govet.Check{},             // Use govet without -shadow
		golint.Check{},            // Enforce Google Go style guide
		dupl.Check{Threshold: 25}, // Identify duplicates
		gosimple.Check{},          // Simplification suggestions
		gostaticcheck.Check{},     // Verify function parameters
	}
	if err := custom.Check("../..."); err != nil {
		t.Fatal("lint failures: %v", err)
	}
}

// initializes a viper object with test configuration
func configure(jsonConfig string) *viper.Viper {
	config := viper.New()
	config.SetConfigType("json")
	config.ReadConfig(bytes.NewBuffer([]byte(jsonConfig)))
	return config
}

var constPass = func(string, string, bool, int) (string, bool, error) {
	return "constant", false, nil
}

func socketDialer(socketAddr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", socketAddr, timeout)
}

func setUpSignerClient(t *testing.T, grpcServer *grpc.Server) (*client.NotarySigner, *grpc.ClientConn, func()) {
	socketFile, err := ioutil.TempFile("", "notary-grpc-test")
	require.NoError(t, err)
	socketFile.Close()
	os.Remove(socketFile.Name())

	lis, err := net.Listen("unix", socketFile.Name())
	require.NoError(t, err, "unable to open socket to listen")

	go grpcServer.Serve(lis)

	// client setup
	clientConn, err := grpc.Dial(socketFile.Name(), grpc.WithInsecure(), grpc.WithDialer(socketDialer))
	require.NoError(t, err, "unable to connect to socket as a GRPC client")

	signerClient := client.NewNotarySigner(clientConn)

	cleanup := func() {
		clientConn.Close()
		grpcServer.Stop()
		os.Remove(socketFile.Name())
	}

	return signerClient, clientConn, cleanup
}

func setUpSignerServer(store trustmanager.KeyStore) *grpc.Server {
	cryptoService := cryptoservice.NewCryptoService(store)
	cryptoServices := signer.CryptoServiceIndex{
		data.ED25519Key: cryptoService,
		data.RSAKey:     cryptoService,
		data.ECDSAKey:   cryptoService,
	}

	//server setup
	grpcServer := grpc.NewServer()
	pb.RegisterKeyManagementServer(grpcServer, &api.KeyManagementServer{
		CryptoServices: cryptoServices,
	})
	pb.RegisterSignerServer(grpcServer, &api.SignerServer{
		CryptoServices: cryptoServices,
	})

	return grpcServer
}

func testTrustService(t *testing.T) (signed.CryptoService, error) {
	tlspart := fmt.Sprintf(`"tls_client_cert": "%s", "tls_client_key": "%s"`,
		Cert, Key)

	var trustRegisterCalled = 0
	var tlsConfig *tls.Config
	var fakeNewSigner = func(_, _ string, c *tls.Config) (*client.NotarySigner, error) {
		tlsConfig = c
		memStore := trustmanager.NewKeyMemoryStore(constPass)
		signerClient, _, _ := setUpSignerClient(t, setUpSignerServer(memStore))
		return signerClient, nil
	}

	trust, _, err := getTrustService(
		configure(fmt.Sprintf(trustTLSConfigTemplate, tlspart)),
		fakeNewSigner, fakeRegisterer(&trustRegisterCalled))
	if err != nil {
		return nil, err
	}
	return trust, nil
}

func testAlternateRoot(cs signed.CryptoService) (*tuf.Repo, error) {
	gun := "quay-root"

	rootPublicKey, err := cs.Create(data.CanonicalRootRole, gun, data.ECDSAKey)
	if err != nil {
		return nil, err
	}
	rootKey, _, err := cs.GetPrivateKey(rootPublicKey.ID())
	if err != nil {
		return nil, err
	}

	// Generate root public key cert
	startTime := time.Now()
	cert, err := cryptoservice.GenerateCertificate(rootKey, gun, startTime, startTime.Add(notary.Year*10))
	if err != nil {
		return nil, err
	}
	x509PublicKey := tufUtils.CertToKey(cert)
	if x509PublicKey == nil {
		return nil, fmt.Errorf("cannot use regenerated certificate: format %v", cert.PublicKeyAlgorithm)
	}

	// Generate root role
	rootRole := data.NewBaseRole(data.CanonicalRootRole, notary.MinThreshold, x509PublicKey)

	// Generate snapshot role
	snapshotKey, err := cs.Create(data.CanonicalSnapshotRole, gun, data.ECDSAKey)
	if err != nil {
		return nil, err
	}
	snapshotRole := data.NewBaseRole(
		data.CanonicalSnapshotRole,
		notary.MinThreshold,
		snapshotKey,
	)

	// Generate targets role
	targetsKey, err := cs.Create(data.CanonicalTargetsRole, gun, data.ECDSAKey)
	if err != nil {
		return nil, err
	}
	targetsRole := data.NewBaseRole(
		data.CanonicalTargetsRole,
		notary.MinThreshold,
		targetsKey,
	)

	// Generate timestamp role
	timestampKey, err := cs.Create(data.CanonicalTimestampRole, gun, data.ECDSAKey)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	if _, err = repo.InitTargets(data.CanonicalTargetsRole); err != nil {
		return nil, err
	}
	if err = repo.InitSnapshot(); err != nil {
		return nil, err
	}
	if err = repo.InitTimestamp(); err != nil {
		return nil, err
	}

	_, err = repo.SignRoot(data.DefaultExpires(data.CanonicalRootRole), nil)
	if err != nil {
		return nil, err
	}
	_, err = repo.SignTargets(data.CanonicalTargetsRole, data.DefaultExpires(data.CanonicalTargetsRole))
	if err != nil {
		return nil, err
	}
	_, err = repo.SignSnapshot(data.DefaultExpires(data.CanonicalSnapshotRole))
	if err != nil {
		return nil, err
	}
	_, err = repo.SignTimestamp(data.DefaultExpires(data.CanonicalTimestampRole))
	if err != nil {
		return nil, err
	}

	return repo, nil
}

func TestGetAddrAndTLSConfigInvalidTLS(t *testing.T) {
	invalids := []string{
		`{"server": {
				"http_addr": ":1234",
				"tls_key_file": "nope"
		}}`,
	}
	for _, configJSON := range invalids {
		_, _, err := getAddrAndTLSConfig(configure(configJSON))
		require.Error(t, err)
	}
}

func TestGetAddrAndTLSConfigNoHTTPAddr(t *testing.T) {
	_, _, err := getAddrAndTLSConfig(configure(fmt.Sprintf(`{
		"server": {
			"tls_cert_file": "%s",
			"tls_key_file": "%s"
		}
	}`, Cert, Key)))
	require.Error(t, err)
	require.Contains(t, err.Error(), "http listen address required for server")
}

func TestGetAddrAndTLSConfigSuccessWithTLS(t *testing.T) {
	httpAddr, tlsConf, err := getAddrAndTLSConfig(configure(fmt.Sprintf(`{
		"server": {
			"http_addr": ":2345",
			"tls_cert_file": "%s",
			"tls_key_file": "%s"
		}
	}`, Cert, Key)))
	require.NoError(t, err)
	require.Equal(t, ":2345", httpAddr)
	require.NotNil(t, tlsConf)
}

func TestGetAddrAndTLSConfigSuccessWithoutTLS(t *testing.T) {
	httpAddr, tlsConf, err := getAddrAndTLSConfig(configure(
		`{"server": {"http_addr": ":2345"}}`))
	require.NoError(t, err)
	require.Equal(t, ":2345", httpAddr)
	require.Nil(t, tlsConf)
}

func TestGetAddrAndTLSConfigWithClientTLS(t *testing.T) {
	httpAddr, tlsConf, err := getAddrAndTLSConfig(configure(fmt.Sprintf(`{
		"server": {
			"http_addr": ":2345",
			"tls_cert_file": "%s",
			"tls_key_file": "%s",
			"client_ca_file": "%s"
		}
	}`, Cert, Key, Root)))
	require.NoError(t, err)
	require.Equal(t, ":2345", httpAddr)
	require.NotNil(t, tlsConf.ClientCAs)
}

func fakeRegisterer(callCount *int) healthRegister {
	return func(_ string, _ time.Duration, _ health.CheckFunc) {
		(*callCount)++
	}

}

// If neither "remote" nor "local" is passed for "trust_service.type", an
// error is returned.
func TestGetInvalidTrustService(t *testing.T) {
	invalids := []string{
		`{"trust_service": {"type": "bruhaha", "key_algorithm": "rsa"}}`,
		`{}`,
	}
	var registerCalled = 0

	for _, config := range invalids {
		_, _, err := getTrustService(configure(config),
			getNotarySigner, fakeRegisterer(&registerCalled))
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"must specify either a \"local\" or \"remote\" type for trust_service")
	}
	// no health function ever registered
	require.Equal(t, 0, registerCalled)
}

// If a local trust service is specified, a local trust service will be used
// with an ED22519 algorithm no matter what algorithm was specified.  No health
// function is configured.
func TestGetLocalTrustService(t *testing.T) {
	localConfig := `{"trust_service": {"type": "local", "key_algorithm": "meh"}}`

	var registerCalled = 0

	trust, algo, err := getTrustService(configure(localConfig),
		getNotarySigner, fakeRegisterer(&registerCalled))
	require.NoError(t, err)
	require.IsType(t, &signed.Ed25519{}, trust)
	require.Equal(t, data.ED25519Key, algo)

	// no health function ever registered
	require.Equal(t, 0, registerCalled)
}

// Invalid key algorithms result in an error if a remote trust service was
// specified.
func TestGetTrustServiceInvalidKeyAlgorithm(t *testing.T) {
	configTemplate := `
	{
		"trust_service": {
			"type": "remote",
			"hostname": "blah",
			"port": "1234",
			"key_algorithm": "%s"
		}
	}`
	badKeyAlgos := []string{
		fmt.Sprintf(configTemplate, ""),
		fmt.Sprintf(configTemplate, data.ECDSAx509Key),
		fmt.Sprintf(configTemplate, "random"),
	}
	var registerCalled = 0

	for _, config := range badKeyAlgos {
		_, _, err := getTrustService(configure(config),
			getNotarySigner, fakeRegisterer(&registerCalled))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key algorithm")
	}
	// no health function ever registered
	require.Equal(t, 0, registerCalled)
}

// template to be used for testing TLS parsing with the trust service
var trustTLSConfigTemplate = `
	{
		"trust_service": {
			"type": "remote",
			"hostname": "notary-signer",
			"port": "1234",
			"key_algorithm": "ecdsa",
			%s
		}
	}`

// Client cert and Key either both have to be empty or both have to be
// provided.
func TestGetTrustServiceTLSMissingCertOrKey(t *testing.T) {
	configs := []string{
		fmt.Sprintf(`"tls_client_cert": "%s"`, Cert),
		fmt.Sprintf(`"tls_client_key": "%s"`, Key),
	}
	var registerCalled = 0

	for _, clientTLSConfig := range configs {
		jsonConfig := fmt.Sprintf(trustTLSConfigTemplate, clientTLSConfig)
		config := configure(jsonConfig)
		_, _, err := getTrustService(config, getNotarySigner,
			fakeRegisterer(&registerCalled))
		require.Error(t, err)
		require.True(t,
			strings.Contains(err.Error(), "either pass both client key and cert, or neither"))
	}
	// no health function ever registered
	require.Equal(t, 0, registerCalled)
}

// If no TLS configuration is provided for the host server, no TLS config will
// be set for the trust service.
func TestGetTrustServiceNoTLSConfig(t *testing.T) {
	config := `{
		"trust_service": {
			"type": "remote",
			"hostname": "notary-signer",
			"port": "1234",
			"key_algorithm": "ecdsa"
		}
	}`
	var registerCalled = 0

	var tlsConfig *tls.Config
	var fakeNewSigner = func(_, _ string, c *tls.Config) (*client.NotarySigner, error) {
		tlsConfig = c
		return &client.NotarySigner{}, nil
	}

	trust, algo, err := getTrustService(configure(config),
		fakeNewSigner, fakeRegisterer(&registerCalled))
	require.NoError(t, err)
	require.IsType(t, &client.NotarySigner{}, trust)
	require.Equal(t, "ecdsa", algo)
	require.Nil(t, tlsConfig.RootCAs)
	require.Nil(t, tlsConfig.Certificates)
	// health function registered
	require.Equal(t, 1, registerCalled)
}

// The rest of the functionality of getTrustService depends upon
// utils.ConfigureClientTLS, so this test just asserts that if successful,
// the correct tls.Config is returned based on all the configuration parameters
func TestGetTrustServiceTLSSuccess(t *testing.T) {
	keypair, err := tls.LoadX509KeyPair(Cert, Key)
	require.NoError(t, err, "Unable to load cert and key for testing")

	tlspart := fmt.Sprintf(`"tls_client_cert": "%s", "tls_client_key": "%s"`,
		Cert, Key)

	var registerCalled = 0

	var tlsConfig *tls.Config
	var fakeNewSigner = func(_, _ string, c *tls.Config) (*client.NotarySigner, error) {
		tlsConfig = c
		return &client.NotarySigner{}, nil
	}

	trust, algo, err := getTrustService(
		configure(fmt.Sprintf(trustTLSConfigTemplate, tlspart)),
		fakeNewSigner, fakeRegisterer(&registerCalled))
	require.NoError(t, err)
	require.IsType(t, &client.NotarySigner{}, trust)
	require.Equal(t, "ecdsa", algo)
	require.Len(t, tlsConfig.Certificates, 1)
	require.True(t, reflect.DeepEqual(keypair, tlsConfig.Certificates[0]))
	// health function registered
	require.Equal(t, 1, registerCalled)
}

// The rest of the functionality of getTrustService depends upon
// utils.ConfigureServerTLS, so this test just asserts that if it fails,
// the error is propagated.
func TestGetTrustServiceTLSFailure(t *testing.T) {
	tlspart := fmt.Sprintf(`"tls_client_cert": "none", "tls_client_key": "%s"`,
		Key)

	var registerCalled = 0

	_, _, err := getTrustService(
		configure(fmt.Sprintf(trustTLSConfigTemplate, tlspart)),
		getNotarySigner, fakeRegisterer(&registerCalled))

	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(),
		"Unable to configure TLS to the trust service"))

	// no health function ever registered
	require.Equal(t, 0, registerCalled)
}

// Just to ensure that errors are propagated
func TestGetStoreInvalid(t *testing.T) {
	config := `{"storage": {"backend": "asdf", "db_url": "doesnt_matter_what_value_this_is"}}`

	var registerCalled = 0
	_, err := getStore(configure(config), nil, nil, fakeRegisterer(&registerCalled))
	require.Error(t, err)

	// no health function ever registered
	require.Equal(t, 0, registerCalled)
}

func TestGetStoreDBStore(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "sqlite3")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	config := fmt.Sprintf(`{"storage": {"backend": "%s", "db_url": "%s"}}`,
		notary.SQLiteBackend, tmpFile.Name())

	var registerCalled = 0

	trust, err := testTrustService(t)
	require.NoError(t, err)
	repo, err := testAlternateRoot(trust)
	require.NoError(t, err)

	store, err := getStore(configure(config), trust, repo, fakeRegisterer(&registerCalled))
	require.NoError(t, err)
	_, ok := store.(*storage.MultiplexingStore)
	require.True(t, ok)

	// health function registered
	require.Equal(t, 1, registerCalled)
}

func TestGetMemoryStore(t *testing.T) {
	var registerCalled = 0

	trust, err := testTrustService(t)
	require.NoError(t, err)
	repo, err := testAlternateRoot(trust)
	require.NoError(t, err)

	config := fmt.Sprintf(`{"storage": {"backend": "%s"}}`, notary.MemoryBackend)
	store, err := getStore(configure(config),trust, repo, fakeRegisterer(&registerCalled))
	require.NoError(t, err)
	_, ok := store.(*storage.MultiplexingStore)
	require.True(t, ok)

	// no health function ever registered
	require.Equal(t, 0, registerCalled)
}

func TestGetCacheConfig(t *testing.T) {
	defaults := `{}`
	valid := `{"caching": {"max_age": {"current_metadata": 0, "consistent_metadata": 31536000}}}`
	invalids := []string{
		`{"caching": {"max_age": {"current_metadata": 0, "consistent_metadata": 31539000}}}`,
		`{"caching": {"max_age": {"current_metadata": -1, "consistent_metadata": 300}}}`,
		`{"caching": {"max_age": {"current_metadata": "hello", "consistent_metadata": 300}}}`,
	}

	current, consistent, err := getCacheConfig(configure(defaults))
	require.NoError(t, err)
	require.Equal(t,
		utils.PublicCacheControl{MaxAgeInSeconds: int(notary.CurrentMetadataCacheMaxAge.Seconds()),
			MustReValidate: true}, current)
	require.Equal(t,
		utils.PublicCacheControl{MaxAgeInSeconds: int(notary.ConsistentMetadataCacheMaxAge.Seconds())}, consistent)

	current, consistent, err = getCacheConfig(configure(valid))
	require.NoError(t, err)
	require.Equal(t, utils.NoCacheControl{}, current)
	require.Equal(t, utils.PublicCacheControl{MaxAgeInSeconds: 31536000}, consistent)

	for _, invalid := range invalids {
		_, _, err := getCacheConfig(configure(invalid))
		require.Error(t, err)
	}
}

func TestGetGUNPRefixes(t *testing.T) {
	valids := map[string][]string{
		`{}`: nil,
		`{"repositories": {"gun_prefixes": []}}`:         nil,
		`{"repositories": {}}`:                           nil,
		`{"repositories": {"gun_prefixes": ["hello/"]}}`: {"hello/"},
	}
	invalids := []string{
		`{"repositories": {"gun_prefixes": " / "}}`,
		`{"repositories": {"gun_prefixes": "nope"}}`,
		`{"repositories": {"gun_prefixes": ["nope"]}}`,
		`{"repositories": {"gun_prefixes": ["/nope/"]}}`,
		`{"repositories": {"gun_prefixes": ["../nope/"]}}`,
	}

	for valid, expected := range valids {
		prefixes, err := getRequiredGunPrefixes(configure(valid))
		require.NoError(t, err)
		require.Equal(t, expected, prefixes)
	}
	for _, invalid := range invalids {
		_, err := getRequiredGunPrefixes(configure(invalid))
		require.Error(t, err, "expected error with %s", invalid)
	}
}
