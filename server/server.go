package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/coreos-inc/apostille/auth"
	ctxutil "github.com/docker/distribution/context"
	registryAuth "github.com/docker/distribution/registry/auth"
	notaryServer "github.com/docker/notary/server"
	"github.com/docker/notary/tuf/signed"
	"github.com/docker/notary/utils"
	"github.com/gorilla/mux"
	"golang.org/x/net/context"

	"github.com/coreos-inc/apostille/storage"

	"github.com/docker/notary"
	"github.com/docker/notary/server/errors"
	"github.com/docker/notary/server/handlers"
	"github.com/docker/notary/tuf"
)

// Config tells Run how to configure a server
type Config struct {
	Addr                         string
	TLSConfig                    *tls.Config
	Trust                        signed.CryptoService
	AuthMethod                   string
	AuthOpts                     interface{}
	RepoPrefixes                 []string
	ConsistentCacheControlConfig utils.CacheControlConfig
	CurrentCacheControlConfig    utils.CacheControlConfig
	QuayRootRepo		     *tuf.Repo
}

// Run sets up and starts a TLS server that can be cancelled using the
// given configuration. The context it is passed is the context it should
// use directly for the TLS server, and generate children off for requests
func Run(ctx context.Context, conf Config) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", conf.Addr)
	if err != nil {
		return err
	}
	var lsnr net.Listener
	lsnr, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}

	if conf.TLSConfig != nil {
		logrus.Info("Enabling TLS")
		lsnr = tls.NewListener(lsnr, conf.TLSConfig)
	}

	var ac registryAuth.AccessController

	if conf.AuthMethod == "quaytoken" {
		authOptions, ok := conf.AuthOpts.(map[string]interface{})
		if !ok {
			return fmt.Errorf("auth.options must be a map[string]interface{}")
		}
		ac, err = auth.NewKeyserverAccessController(authOptions)
		if err != nil {
			return err
		}
	} else if conf.AuthMethod == "testing" {
		logrus.Warn("Test Auth config enabled - all requests will be authorized as user 'test_user'")
		ac = auth.NewTestingAccessController("test_user")
	} else {
		return fmt.Errorf("No auth config supplied - use 'testing' if mock auth is desired")
	}

	svr := http.Server{
		Addr: conf.Addr,
		Handler: TrustMultiplexerHandler(ac, ctx, conf.Trust,
			conf.ConsistentCacheControlConfig,
			conf.CurrentCacheControlConfig,
			conf.RepoPrefixes,
		),
	}
	logrus.Info("Starting on ", conf.Addr)
	err = svr.Serve(lsnr)
	return err
}

// GetMetadataHandler returns the json for a specified role and GUN.
// It determines which root of trust to use based on the requesting user.
func GetMetadataHandler(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	defer r.Body.Close()
	vars := mux.Vars(r)

	username := storage.Username("")
	if userInfo, ok := ctx.Value("auth.user").(registryAuth.UserInfo); ok {
		username = storage.Username(userInfo.Name)
	}
	gun := storage.GUN(vars["gun"])
	s := ctx.Value(notary.CtxKeyMetaStore)
	logger := ctxutil.GetLoggerWithFields(ctx, map[interface{}]interface{}{
		"gun":      gun,
		"username": username,
	}, "gun", "username")

	store, ok := s.(storage.MultiplexingMetaStore)
	if !ok {
		logger.Error("500 GET: no storage exists")
		return errors.ErrNoStorage.WithDetail(nil)
	}

	// If user is listed as a signing_user, serve "signer" root
	// signing users must have push access
	if store.IsSigner(username, gun) {
		logger.Info("request user is a signer for this repo")
		ctx = context.WithValue(ctx, notary.CtxKeyMetaStore, store.SignerRootMetaStore())
	} else {
		logger.Info("request user is not signer for this repo, will be served shared root")
		ctx = context.WithValue(ctx, notary.CtxKeyMetaStore, store.AlternateRootMetaStore())
	}
	return handlers.GetHandler(ctx, w, r)
}

// UserScopedAtomicUpdateHandler records the username of the incoming request on the metastore, then proxies to
// notary server's AtomicUpdateHandler
func UserScopedAtomicUpdateHandler(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	defer r.Body.Close()
	vars := mux.Vars(r)

	username := storage.Username("")
	if userInfo, ok := ctx.Value("auth.user").(registryAuth.UserInfo); ok {
		username = storage.Username(userInfo.Name)
	}
	gun := storage.GUN(vars["gun"])

	s := ctx.Value(notary.CtxKeyMetaStore)
	logger := ctxutil.GetLoggerWithField(ctx, gun, "gun")

	store, ok := s.(storage.MultiplexingMetaStore)
	if !ok {
		logger.Error("500 GET: no storage exists")
		return errors.ErrNoStorage.WithDetail(nil)
	}

	// User must have push access to get here, so we know the user is a signer
	if !store.IsSigner(username, gun) {
		logger.Infof("Adding %s as a signer for %s", username, gun)
		if err := store.AddUserAsSigner(username, gun); err != nil {
			logger.Error("Unable to add %s as a signer for %s: %v", username, gun, err)
		}
	}

	return handlers.AtomicUpdateHandler(ctx, w, r)
}

// TrustMutliplexerHandler wraps a standard notary server router and
// splits access to different trust roots based on request criteria,
// e.g. username or URL.
func TrustMultiplexerHandler(ac registryAuth.AccessController, ctx context.Context, trust signed.CryptoService,
	consistent, current utils.CacheControlConfig, repoPrefixes []string) http.Handler {
	r := mux.NewRouter()

	// Standard Notary server handler; calls that we don't care about will be routed here
	notaryHandler := notaryServer.RootHandler(
		ctx, ac, trust,
		consistent,
		current,
		repoPrefixes,
	)

	authWrapper := utils.RootHandlerFactory(ctx, ac, trust)
	notFoundError := errors.ErrMetadataNotFound.WithDetail(nil)

	// Intercept POST requests to record which user created the TUF repo
	r.Methods("POST").Path("/v2/{gun:.*}/_trust/tuf/").Handler(notaryServer.CreateHandler(notaryServer.EndpointConfig{
		OperationName:       "UpdateTUF",
		ErrorIfGUNInvalid:   errors.ErrMetadataNotFound.WithDetail(nil),
		ServerHandler:       UserScopedAtomicUpdateHandler,
		PermissionsRequired: []string{"push", "pull"},
		AuthWrapper:         authWrapper,
		RepoPrefixes:        repoPrefixes,
	}))

	// Intercept GET requests for TUF metadata, so we can serve different roots based on username
	r.Methods("GET").Path("/v2/{gun:[^*]+}/_trust/tuf/{tufRole:root|targets(?:/[^/\\s]+)*|snapshot|timestamp}.{checksum:[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128}}.json").Handler(notaryServer.CreateHandler(notaryServer.EndpointConfig{
		OperationName:       "GetRoleByHash",
		ErrorIfGUNInvalid:   notFoundError,
		IncludeCacheHeaders: true,
		CacheControlConfig:  consistent,
		ServerHandler:       GetMetadataHandler,
		PermissionsRequired: []string{"pull"},
		AuthWrapper:         authWrapper,
		RepoPrefixes:        repoPrefixes,
	}))
	r.Methods("GET").Path("/v2/{gun:[^*]+}/_trust/tuf/{version:[1-9]*[0-9]+}.{tufRole:root|targets(?:/[^/\\s]+)*|snapshot|timestamp}.json").Handler(notaryServer.CreateHandler(notaryServer.EndpointConfig{
		OperationName:       "GetRoleByVersion",
		ErrorIfGUNInvalid:   notFoundError,
		IncludeCacheHeaders: true,
		CacheControlConfig:  consistent,
		ServerHandler:       GetMetadataHandler,
		PermissionsRequired: []string{"pull"},
		AuthWrapper:         authWrapper,
		RepoPrefixes:        repoPrefixes,
	}))
	r.Methods("GET").Path("/v2/{gun:[^*]+}/_trust/tuf/{tufRole:root|targets(?:/[^/\\s]+)*|snapshot|timestamp}.json").Handler(notaryServer.CreateHandler(notaryServer.EndpointConfig{
		OperationName:       "GetRole",
		ErrorIfGUNInvalid:   notFoundError,
		IncludeCacheHeaders: true,
		CacheControlConfig:  current,
		ServerHandler:       GetMetadataHandler,
		PermissionsRequired: []string{"pull"},
		AuthWrapper:         authWrapper,
		RepoPrefixes:        repoPrefixes,
	}))

	// Everything else is handled with standard notary handlers
	r.Methods("GET", "POST", "PUT", "HEAD", "DELETE").Path("/{other:.*}").Handler(notaryHandler)
	return r
}
