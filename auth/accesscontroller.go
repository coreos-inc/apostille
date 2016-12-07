package auth

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/docker/distribution/context"
	registryAuth "github.com/docker/distribution/registry/auth"
	registryToken "github.com/docker/distribution/registry/auth/token"
	"github.com/docker/libtrust"
)

// keyserverAccessController implements the auth.AccessController interface.
type keyserverAccessController struct {
	realm     string
	issuer    string
	service   string
	keyserver string
}

// tokenAccessOptions is a convenience type for handling
// options to the contstructor of a keyserverAccessController.
type tokenAccessOptions struct {
	realm     string
	issuer    string
	service   string
	keyserver string
}

// checkOptions gathers the necessary options
// for a keyserverAccessController from the given map.
func checkOptions(options map[string]interface{}) (tokenAccessOptions, error) {
	var opts tokenAccessOptions

	keys := []string{"realm", "issuer", "service", "keyserver"}
	vals := make([]string, 0, len(keys))
	for _, key := range keys {
		val, ok := options[key].(string)
		if !ok {
			return opts, fmt.Errorf("quay token auth requires a valid option string: %q", key)
		}
		vals = append(vals, val)
	}

	opts.realm, opts.issuer, opts.service, opts.keyserver = vals[0], vals[1], vals[2], vals[3]

	return opts, nil
}

// NewKeyserverAccessController creates a keyserverAccessController using the given options.
func NewKeyserverAccessController(options map[string]interface{}) (registryAuth.AccessController, error) {
	config, err := checkOptions(options)
	if err != nil {
		return nil, err
	}
	return &keyserverAccessController{
		realm:     config.realm,
		issuer:    config.issuer,
		service:   config.service,
		keyserver: config.keyserver,
	}, nil
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

	url := fmt.Sprintf("%s/services/%s/keys/%s", ac.keyserver, ac.service, token.Header.KeyID)
	logrus.Infof("fetching jwk from keyserver: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		challenge.err = err
		return nil, challenge
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		challenge.err = err
		return nil, challenge
	}

	// parse into pubKey
	pubKey, err := libtrust.UnmarshalPublicKeyJWK(body)
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
