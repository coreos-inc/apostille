package auth

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	"encoding/json"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/docker/distribution/context"
	registryAuth "github.com/docker/distribution/registry/auth"
	registryToken "github.com/docker/distribution/registry/auth/token"
	"github.com/docker/libtrust"
)

// keyserverAccessController implements the auth.AccessController interface.
type keyserverAccessController struct {
	realm             string
	issuer            string
	service           string
	keyserver         string
	updateKeyInterval time.Duration
	keysLock          sync.RWMutex
	keys              map[string]libtrust.PublicKey
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
	Keys []json.RawMessage `json:"key"`
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

	token, err := registryToken.NewToken(rawToken)
	if err != nil {
		challenge.err = err
		return nil, challenge
	}

	ac.keysLock.RLock()
	pubKey, ok := ac.keys[token.Header.KeyID]
	ac.keysLock.RUnlock()
	if !ok {
		pubKey, err = ac.tryFindKey(token.Header.KeyID)
		if err != nil {
			challenge.err = err
			return nil, challenge
		}
	}

	if err != nil {
		challenge.err = fmt.Errorf("unable to decode JWK value: %s", err)
		return nil, challenge
	}
	if err = VerifyNonX509(token, ac.issuer, ac.service, pubKey); err != nil {
		challenge.err = err
		return nil, challenge
	}

	accessSet := AccessSet(token)
	for _, access := range accessItems {
		if !accessSet.contains(access) {
			challenge.err = registryToken.ErrInsufficientScope
			return nil, challenge
		}
	}

	return registryAuth.WithUser(ctx, registryAuth.UserInfo{Name: token.Claims.Subject}), nil
}

// VerifyNonX509 attempts to verify this token using the given options.
// Returns a nil error if the token is valid.
// Unlike standard Token verification, does not expect a cert chain.
func VerifyNonX509(token *registryToken.Token, issuer, service string, signingKey libtrust.PublicKey) error {
	// Verify that the Issuer claim is a trusted authority.
	if issuer != token.Claims.Issuer {
		logrus.Infof("token from untrusted issuer: %q", token.Claims.Issuer)
		return registryToken.ErrInvalidToken
	}

	// Verify that the Audience claim is allowed.
	if service != token.Claims.Audience {
		logrus.Infof("token intended for another audience: %q", token.Claims.Audience)
		return registryToken.ErrInvalidToken
	}

	// Verify that the token is currently usable and not expired.
	currentTime := time.Now()

	ExpWithLeeway := time.Unix(token.Claims.Expiration, 0).Add(Leeway)
	if currentTime.After(ExpWithLeeway) {
		logrus.Infof("token not to be used after %s - currently %s", ExpWithLeeway, currentTime)
		return registryToken.ErrInvalidToken
	}

	NotBeforeWithLeeway := time.Unix(token.Claims.NotBefore, 0).Add(-Leeway)
	if currentTime.Before(NotBeforeWithLeeway) {
		logrus.Infof("token not to be used before %s - currently %s", NotBeforeWithLeeway, currentTime)
		return registryToken.ErrInvalidToken
	}

	// Verify the token signature.
	if len(token.Signature) == 0 {
		logrus.Info("token has no signature")
		return registryToken.ErrInvalidToken
	}

	// Finally, verify the signature of the token using the key which signed it.
	if err := signingKey.Verify(strings.NewReader(token.Raw), token.Header.SigningAlg, token.Signature); err != nil {
		logrus.Infof("unable to verify token signature: %s", err)
		return registryToken.ErrInvalidToken
	}

	return nil
}

// AccessSet returns a set of actions available for the resource
// actions listed in the `access` section of the token.
func AccessSet(token *registryToken.Token) accessSet {
	if token.Claims == nil {
		return nil
	}

	accessSet := make(accessSet, len(token.Claims.Access))

	for _, resourceActions := range token.Claims.Access {
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
	err = json.NewDecoder(resp.Body).Decode(&maybeKeys)
	if err != nil {
		logrus.Errorln("failed to decode JWK JSON: " + err.Error())
		return err
	}

	keys := make(map[string]libtrust.PublicKey)
	for _, maybeKey := range maybeKeys.Keys {
		pubKey, err := libtrust.UnmarshalPublicKeyJWK(maybeKey)
		if err != nil {
			logrus.Errorln("failed to decode JWK into public key: " + err.Error())
			return err
		}
		keys[pubKey.KeyID()] = pubKey
	}

	ac.keysLock.Lock()
	ac.keys = keys
	ac.keysLock.Unlock()
	logrus.Infof("successfully fetched JWK Set")
	return nil
}

func (ac *keyserverAccessController) tryFindKey(keyId string) (libtrust.PublicKey, error) {
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
	pubKey, err := libtrust.UnmarshalPublicKeyJWK(body)
	if err != nil {
		return nil, fmt.Errorf("unable to decode JWK value: %s", err)
	}
	return pubKey, nil
}
