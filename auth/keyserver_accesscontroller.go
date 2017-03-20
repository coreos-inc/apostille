package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"errors"

	"github.com/Sirupsen/logrus"
	"github.com/docker/distribution/context"
	registryAuth "github.com/docker/distribution/registry/auth"
	registryToken "github.com/docker/distribution/registry/auth/token"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	TufRootSigner  string = "com.apostille.root"
	TokenSeparator        = "."
)

// keyserverAccessController implements the auth.AccessController interface.
type keyserverAccessController struct {
	realm             string
	issuer            string
	service           string
	keyserver         string
	updateKeyInterval time.Duration
	keysLock          sync.RWMutex
	keys              map[string]*jose.JSONWebKey
}

// tokenAccessOptions is a convenience type for handling
// options to the constructor of a keyserverAccessController.
type tokenAccessOptions struct {
	realm             string
	issuer            string
	service           string
	keyserver         string
	updateKeyInterval time.Duration
}

type Keys struct {
	Keys []json.RawMessage `json:"keys"`
}

type JWTContext struct {
	Context map[string]string `json:"context"`
}

// checkOptions gathers the necessary options
// for a keyserverAccessController from the given map.
func checkOptions(options map[string]interface{}) (tokenAccessOptions, error) {
	var opts tokenAccessOptions

	keys := []string{"realm", "issuer", "service", "keyserver", "updateKeyInterval"}
	vals := make([]string, 0, len(keys))
	for _, key := range keys {
		val, ok := options[key].(string)
		if !ok {
			return opts, fmt.Errorf("quay token auth requires a valid option string: %q", key)
		}
		vals = append(vals, val)
	}

	val, err := time.ParseDuration(vals[4])
	if err != nil {
		return opts, fmt.Errorf("invalid duration specified for key refresh interval: %s",
			err.Error())
	}

	opts.realm, opts.issuer, opts.service, opts.keyserver = vals[0], vals[1], vals[2], vals[3]
	opts.updateKeyInterval = val
	return opts, nil
}

// NewKeyserverAccessController creates a keyserverAccessController using the given options.
func NewKeyserverAccessController(options map[string]interface{}) (registryAuth.AccessController, error) {
	config, err := checkOptions(options)
	if err != nil {
		return nil, err
	}
	accessController := &keyserverAccessController{
		realm:             config.realm,
		issuer:            config.issuer,
		service:           config.service,
		keyserver:         config.keyserver,
		updateKeyInterval: config.updateKeyInterval,
	}
	accessController.updateKeys()
	go func() {
		for {
			select {
			case <-time.After(accessController.updateKeyInterval):
				logrus.Debug("performing fetch of JWKs")
				accessController.updateKeys()
			}
		}
	}()
	return accessController, nil
}

// Authorized handles checking whether the given request is authorized
// for actions on resources described by the given access items.
func (ac *keyserverAccessController) Authorized(ctx context.Context, accessItems ...registryAuth.Access) (context.Context, error) {
	challenge := &authChallenge{
		realm:     ac.realm,
		service:   ac.service,
		accessSet: newAccessSet(accessItems...),
	}

	req, err := context.GetRequest(ctx)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(req.Header.Get("Authorization"), " ")

	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		challenge.err = registryToken.ErrTokenRequired
		return nil, challenge
	}

	rawToken := parts[1]

	token, err := jwt.ParseSigned(rawToken)
	if err != nil {
		challenge.err = err
		return nil, challenge
	}
	if len(token.Headers) < 1 {
		challenge.err = fmt.Errorf("invalid JWT: no header")
		return nil, challenge
	}
	keyID := token.Headers[0].KeyID

	ac.keysLock.RLock()
	pubKey, ok := ac.keys[keyID]
	ac.keysLock.RUnlock()
	if !ok {
		pubKey, err = ac.tryFindKey(keyID)
		if err != nil {
			challenge.err = err
			return nil, challenge
		}
	}

	if err != nil {
		challenge.err = fmt.Errorf("unable to decode JWK value: %s", err)
		return nil, challenge
	}

	claims := jwt.Claims{}
	access := AccessClaim{}
	if err := token.Claims(pubKey, &claims, &access); err != nil {
		challenge.err = err
		return nil, challenge
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:   ac.issuer,
		Audience: []string{ac.service},
	}, Leeway); err != nil {
		challenge.err = err
		return nil, challenge
	}

	accessSet := AccessSet(access)
	for _, access := range accessItems {
		if !accessSet.contains(access) {
			challenge.err = registryToken.ErrInsufficientScope
			return nil, challenge
		}
	}

	jwtContext, err := getContext(rawToken)
	if err != nil {
		challenge.err = err
		return nil, challenge
	}

	tufRootSigner, err := getTufRootSigner(jwtContext)
	if err != nil {
		challenge.err = err
		return nil, challenge
	}

	return context.WithValue(ctx, TufRootSigner, tufRootSigner), nil
}

// AccessSet returns a set of actions available for the resource
// actions listed in the `access` section of the token.
func AccessSet(claim AccessClaim) accessSet {
	accessSet := make(accessSet, len(claim.Access))

	for _, resourceActions := range claim.Access {
		resource := registryAuth.Resource{
			Type: resourceActions.Type,
			Name: resourceActions.Name,
		}

		set, exists := accessSet[resource]
		if !exists {
			set = newActionSet()
			accessSet[resource] = set
		}

		for _, action := range resourceActions.Actions {
			set.add(action)
		}
	}

	return accessSet
}

func (ac *keyserverAccessController) updateKeys() error {
	url := fmt.Sprintf("%s/services/%s/keys", ac.keyserver, ac.service)
	logrus.Infof("fetching jwk from keyserver: %s", url)
	resp, err := http.Get(url)
	if err != nil {
		logrus.Errorln("failed to fetch JWK Set: " + err.Error())
		return err
	}
	defer resp.Body.Close()

	var maybeKeys Keys

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorln("failed to read JWK set: " + err.Error())
		return err
	}
	err = json.Unmarshal(respBytes, &maybeKeys)
	if err != nil {
		logrus.Errorln("failed to decode JWK JSON: " + err.Error())
		return err
	}

	keys := make(map[string]*jose.JSONWebKey)
	for i, maybeKey := range maybeKeys.Keys {
		jwk := jose.JSONWebKey{}
		if err = jwk.UnmarshalJSON(maybeKey); err != nil {
			logrus.Errorf("unable to decode JWK #%d value: %s", i, err)
			continue
		}

		if !jwk.Valid() {
			logrus.Errorf("JWK #%d invalid: %v", i, jwk)
			continue
		}

		keys[jwk.KeyID] = &jwk
	}
	if len(keys) == 0 {
		return fmt.Errorf("no valid keys found")
	}
	ac.keysLock.Lock()
	ac.keys = keys
	ac.keysLock.Unlock()
	logrus.Infof("successfully fetched JWK Set: %d keys", len(keys))
	return nil
}

func (ac *keyserverAccessController) tryFindKey(keyId string) (*jose.JSONWebKey, error) {
	url := fmt.Sprintf("%s/services/%s/keys/%s", ac.keyserver, ac.service, keyId)
	logrus.Infof("fetching jwk from keyserver: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// parse into pubKey
	jwk := jose.JSONWebKey{}
	if err = jwk.UnmarshalJSON(body); err != nil {
		return nil, fmt.Errorf("unable to decode JWK value: %s", err)
	}

	if !jwk.Valid() {
		return nil, fmt.Errorf("JWK invalid: %v", jwk)
	}

	return &jwk, nil
}

func getTufRootSigner(myToken *JWTContext) (string, error) {
	tufRootSigner, ok := myToken.Context[TufRootSigner]
	if !ok || tufRootSigner == "" {
		return "", errors.New("No TUF root signer key")
	}
	return tufRootSigner, nil
}

func getContext(rawToken string) (*JWTContext, error) {
	rawClaims := strings.Split(rawToken, TokenSeparator)[1]

	var (
		contextJson       []byte
		err               error
		ErrMalformedToken = errors.New("malformed token")
	)

	if contextJson, err = base64.URLEncoding.DecodeString(rawClaims); err != nil {
		err = fmt.Errorf("unable to decode claims: %s", err)
		return nil, ErrMalformedToken
	}

	jwtContext := new(JWTContext)

	if err = json.Unmarshal(contextJson, jwtContext); err != nil {
		err = fmt.Errorf("unable to unmarshal jwt context: %s", err)
		return nil, ErrMalformedToken
	}

	return jwtContext, nil
}
