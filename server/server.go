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
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	"github.com/docker/notary/utils"
	"github.com/gorilla/mux"
	"golang.org/x/net/context"

	"github.com/coreos-inc/apostille/storage"

	"github.com/docker/notary"
	"github.com/docker/notary/server/errors"
	"github.com/docker/notary/server/handlers"
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
	Admin                        bool
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
		ac = auth.NewConstantAccessController("signer")
	} else if conf.AuthMethod == "admin" {
		ac = auth.NewConstantAccessController("admin")
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
	serverName := "apostille"
	if conf.Admin {
		serverName += " admin"
	}
	logrus.Infof("Starting %s server on %s", serverName, conf.Addr)
	err = svr.Serve(lsnr)
	return err
}

// GetMetadataHandler returns the json for a specified role and GUN.
// It determines which root of trust to use based on the requesting user.
func GetMetadataHandler(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	defer r.Body.Close()
	vars := mux.Vars(r)
	tufRootSigner := ctx.Value(auth.TufRootSigner)
	gun := data.GUN(vars["gun"])
	s := ctx.Value(notary.CtxKeyMetaStore)
	logger := ctxutil.GetLoggerWithFields(ctx, map[interface{}]interface{}{
		"gun":     gun,
		"tufRoot": tufRootSigner,
	}, "gun", "tufRoot")

	// If user is listed as a signing user, serve "signer" root
	// signing users must have push access
	switch tufRootSigner {
	case "signer":
		store, ok := s.(*storage.MultiplexingStore)
		if !ok {
			logger.Error("500 GET: no storage exists")
			return errors.ErrNoStorage.WithDetail(nil)
		}
		ctx = context.WithValue(ctx, notary.CtxKeyMetaStore, store.SignerChannelMetaStore)
	case "quay":
		store, ok := s.(*storage.MultiplexingStore)
		if !ok {
			logger.Error("500 GET: no storage exists")
			return errors.ErrNoStorage.WithDetail(nil)
		}
		ctx = context.WithValue(ctx, notary.CtxKeyMetaStore, store.AlternateChannelMetaStore)
	case "admin":
		store, ok := s.(*storage.ChannelMetastore)
		if !ok {
			logger.Error("500 GET: no storage exists")
			return errors.ErrNoStorage.WithDetail(s)
		}
		ctx = context.WithValue(ctx, notary.CtxKeyMetaStore, store)
	default:
		return errors.ErrMetadataNotFound.WithDetail(fmt.Sprintf("Invalid tuf root signer %s", tufRootSigner))
	}
	return handlers.GetHandler(ctx, w, r)
}

// AtomicUpdateHandler handles the switch to the admin repo if needed
// It determines which root of trust to use based on the requesting user.
func AtomicUpdateHandler(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	defer r.Body.Close()
	vars := mux.Vars(r)
	tufRootSigner := ctx.Value(auth.TufRootSigner)
	gun := data.GUN(vars["gun"])
	s := ctx.Value(notary.CtxKeyMetaStore)
	logger := ctxutil.GetLoggerWithFields(ctx, map[interface{}]interface{}{
		"gun":     gun,
		"tufRoot": tufRootSigner,
	}, "gun", "tufRoot")

	if tufRootSigner == "admin" {
		logger.Info("request user is on the admin interface, will update shared root")
		store, ok := s.(*storage.ChannelMetastore)
		if !ok {
			logger.Error("500 GET: no storage exists")
			return errors.ErrNoStorage.WithDetail(s)
		}
		ctx = context.WithValue(ctx, notary.CtxKeyMetaStore, store)
	}
	return handlers.AtomicUpdateHandler(ctx, w, r)
}

// TrustMutliplexerHandler wraps a standard notary server router and
// splits access to different trust roots based on request criteria,
// e.g. username or URL.
func TrustMultiplexerHandler(ac registryAuth.AccessController, ctx context.Context, trust signed.CryptoService,
	consistent, current utils.CacheControlConfig, repoPrefixes []string) http.Handler {
	r := mux.NewRouter()

	authWrapper := utils.RootHandlerFactory(ctx, ac, trust)
	notFoundError := errors.ErrMetadataNotFound.WithDetail(nil)
	invalidGUNErr := errors.ErrInvalidGUN.WithDetail(fmt.Sprintf("Require GUNs with prefix: %v", repoPrefixes))

	// Standard Notary server handler; calls that we don't care about will be routed here
	notaryHandler := notaryServer.RootHandler(
		ctx, ac, trust,
		consistent,
		current,
		repoPrefixes,
	)

	r.Methods("GET").Path("/v2/").Handler(authWrapper(handlers.MainHandler))

	// Intercept GET requests for TUF metadata, so we can serve different roots based on username
	r.Methods("GET").Path("/v2/{gun:.*}/_trust/tuf/{tufRole:root|targets(?:/[^/\\s]+)*|snapshot|timestamp}.{checksum:[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128}}.json").Handler(notaryServer.CreateHandler(
		"GetRoleByHash",
		GetMetadataHandler,
		notFoundError,
		true,
		utils.NoCacheControl{},
		[]string{"pull"},
		authWrapper,
		repoPrefixes,
	))
	r.Methods("GET").Path("/v2/{gun:.*}/_trust/tuf/{version:[1-9]*[0-9]+}.{tufRole:root|targets(?:/[^/\\s]+)*|snapshot|timestamp}.json").Handler(notaryServer.CreateHandler(
		"GetRoleByVersion",
		GetMetadataHandler,
		notFoundError,
		true,
		utils.NoCacheControl{},
		[]string{"pull"},
		authWrapper,
		repoPrefixes,
	))
	r.Methods("GET").Path("/v2/{gun:.*}/_trust/tuf/{tufRole:root|targets(?:/[^/\\s]+)*|snapshot|timestamp}.json").Handler(notaryServer.CreateHandler(
		"GetRole",
		GetMetadataHandler,
		notFoundError,
		true,
		utils.NoCacheControl{},
		[]string{"pull"},
		authWrapper,
		repoPrefixes,
	))

	// Intercept requests with the `gun` because notary doesn't parse them correctly if they have a *
	r.Methods("POST").Path("/v2/{gun:.*}/_trust/tuf/").Handler(notaryServer.CreateHandler(
		"UpdateTUF",
		AtomicUpdateHandler,
		invalidGUNErr,
		false,
		nil,
		[]string{"push", "pull"},
		authWrapper,
		repoPrefixes,
	))
	r.Methods("GET").Path(
		"/v2/{gun:.*}/_trust/tuf/{tufRole:snapshot|timestamp}.key").Handler(notaryServer.CreateHandler(
		"GetKey",
		handlers.GetKeyHandler,
		notFoundError,
		false,
		nil,
		[]string{"push", "pull"},
		authWrapper,
		repoPrefixes,
	))
	r.Methods("POST").Path(
		"/v2/{gun:.*}/_trust/tuf/{tufRole:snapshot|timestamp}.key").Handler(notaryServer.CreateHandler(
		"RotateKey",
		handlers.RotateKeyHandler,
		notFoundError,
		false,
		nil,
		[]string{"*"},
		authWrapper,
		repoPrefixes,
	))
	r.Methods("DELETE").Path("/v2/{gun:.*}/_trust/tuf/").Handler(notaryServer.CreateHandler(
		"DeleteTUF",
		handlers.DeleteHandler,
		notFoundError,
		false,
		nil,
		[]string{"*"},
		authWrapper,
		repoPrefixes,
	))
	r.Methods("GET").Path("/v2/{gun:.*}/_trust/changefeed").Handler(notaryServer.CreateHandler(
		"Changefeed",
		handlers.Changefeed,
		notFoundError,
		false,
		nil,
		[]string{"pull"},
		authWrapper,
		repoPrefixes,
	))

	r.Methods("GET", "POST", "PUT", "HEAD", "DELETE").Path("/{other:.*}").Handler(notaryHandler)

	return r
}
