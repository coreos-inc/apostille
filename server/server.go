package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/Sirupsen/logrus"
	ctxutil "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/auth"
	notaryServer "github.com/docker/notary/server"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	"github.com/docker/notary/utils"
	"github.com/gorilla/mux"
	"golang.org/x/net/context"

	"github.com/coreos-inc/apostille/storage"

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

	var ac auth.AccessController
	if conf.AuthMethod == "token" {
		authOptions, ok := conf.AuthOpts.(map[string]interface{})
		if !ok {
			return fmt.Errorf("auth.options must be a map[string]interface{}")
		}
		ac, err = auth.GetAccessController(conf.AuthMethod, authOptions)
		if err != nil {
			return err
		}
	}

	// The normal notary handler, which is given all requests that we don't care about

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

	username := storage.Username(ctxutil.GetStringValue(ctx, "auth.user.name"))
	gun := storage.GUN(vars["imageName"])
	s := ctx.Value("metaStore")
	logger := ctxutil.GetLoggerWithField(ctx, gun, "gun")
	store, ok := s.(storage.SignerMetaStore)
	if !ok {
		logger.Error("500 GET: no storage exists")
		return errors.ErrNoStorage.WithDetail(nil)
	}

	// Query DB to find out which root should be served for (username, gun)
	userIsSigner := false
	if username != "" && store.IsSigner(username, gun) {
		userIsSigner = true
	}

	// If user is listed as a signing_user, serve "signer" root
	// signing users must have push access
	if userIsSigner {
		return handlers.GetHandler(ctx, w, r)
	}

	// If not in list of signing users, serve Quay root
	tufRole := vars["tufRole"]
	if tufRole == data.CanonicalRootRole {
		// serve alternate root
		return handlers.GetHandler(ctx, w, r)

	} else if tufRole == data.CanonicalSnapshotRole {
		// serve alternate snapshot
		return handlers.GetHandler(ctx, w, r)

	} else {
		// serve normal timestamp/targets
		return handlers.GetHandler(ctx, w, r)
	}
	return nil
}

// TrustMutliplexerHandler wraps a standard notary server router and
// splits access to different trust roots based on request criteria,
// e.g. username or URL.
func TrustMultiplexerHandler(ac auth.AccessController, ctx context.Context, trust signed.CryptoService,
	consistent, current utils.CacheControlConfig, repoPrefixes []string) http.Handler {
	r := mux.NewRouter()

	// Standard Notary server handler; calls that we don't care about will be routed here
	notaryHandler := notaryServer.RootHandler(
		ac, ctx, trust,
		consistent,
		current,
		repoPrefixes,
	)

	// Intercept GET requests for TUF metadata, so we can serve different roots based on username
	r.Methods("GET").Path("/v2/{imageName:.*}/_trust/tuf/{tufRole:root|targets(?:/[^/\\s]+)*|snapshot|timestamp}.json").Handler(notaryServer.CreateHandler(notaryServer.ServerEndpoint{
		OperationName:       "GetRole",
		ErrorIfGUNInvalid:   errors.ErrMetadataNotFound.WithDetail(nil),
		IncludeCacheHeaders: true,
		CacheControlConfig:  current,
		ServerHandler:       GetMetadataHandler,
		PermissionsRequired: []string{"pull"},
		AuthWrapper:         utils.RootHandlerFactory(ac, ctx, trust),
		RepoPrefixes:        repoPrefixes,
	}))

	// Everything else is handled with standard notary handlers
	r.Methods("GET", "POST", "PUT", "HEAD", "DELETE").Path("/{other:.*}").Handler(notaryHandler)
	return r
}
