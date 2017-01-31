package test

import (
	"github.com/stretchr/testify/require"
	"os"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/signer"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	"github.com/docker/notary/tuf"
	"github.com/docker/notary"
	"time"
	"net"
	"testing"
	"google.golang.org/grpc"
	"github.com/docker/notary/signer/client"
	"io/ioutil"
	pb "github.com/docker/notary/proto"
	"github.com/docker/notary/signer/api"
	tufUtils "github.com/docker/notary/tuf/utils"
)

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

func TrustServiceMock(t *testing.T) signed.CryptoService {
	memStore := trustmanager.NewKeyMemoryStore(constPass)
	trust, _, _ := setUpSignerClient(t, setUpSignerServer(memStore))
	return trust
}

func AlternateRootRepoMock(t *testing.T, cs signed.CryptoService, gun string) *tuf.Repo {

	rootPublicKey, err := cs.Create(data.CanonicalRootRole, gun, data.ECDSAKey)
	require.NoError(t, err)
	rootKey, _, err := cs.GetPrivateKey(rootPublicKey.ID())
	require.NoError(t, err)

	// Generate root public key cert
	startTime := time.Now()
	cert, err := cryptoservice.GenerateCertificate(rootKey, gun, startTime, startTime.Add(notary.Year*10))
	require.NoError(t, err)
	x509PublicKey := tufUtils.CertToKey(cert)
	require.NoError(t, err)

	// Generate root role
	rootRole := data.NewBaseRole(data.CanonicalRootRole, notary.MinThreshold, x509PublicKey)

	// Generate snapshot role
	snapshotKey, err := cs.Create(data.CanonicalSnapshotRole, gun, data.ECDSAKey)
	require.NoError(t, err)
	snapshotRole := data.NewBaseRole(
		data.CanonicalSnapshotRole,
		notary.MinThreshold,
		snapshotKey,
	)

	// Generate targets role
	targetsKey, err := cs.Create(data.CanonicalTargetsRole, gun, data.ECDSAKey)
	require.NoError(t, err)
	targetsRole := data.NewBaseRole(
		data.CanonicalTargetsRole,
		notary.MinThreshold,
		targetsKey,
	)

	// Generate timestamp role
	timestampKey, err := cs.Create(data.CanonicalTimestampRole, gun, data.ECDSAKey)
	require.NoError(t, err)
	timestampRole := data.NewBaseRole(
		data.CanonicalTimestampRole,
		notary.MinThreshold,
		timestampKey,
	)

	// Generate full repo
	repo := tuf.NewRepo(cs)
	err = repo.InitRoot(rootRole, timestampRole, snapshotRole, targetsRole, false)
	require.NoError(t, err)

	_, err = repo.InitTargets(data.CanonicalTargetsRole)
	require.NoError(t, err)
	repo.InitSnapshot()
	require.NoError(t, err)
	repo.InitTimestamp()
	require.NoError(t, err)

	return repo
}
