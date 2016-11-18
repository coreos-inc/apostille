package auth

// This file contains vendored code from docker/distribution
// Vendoring is necessary because these objects/methods are private

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	registryAuth "github.com/docker/distribution/registry/auth"
	registryToken "github.com/docker/distribution/registry/auth/token"
)

// Leeway is the Duration that will be added to NBF and EXP claim
// checks to account for clock skew as per https://tools.ietf.org/html/rfc7519#section-4.1.5
const Leeway = 60 * time.Second

// stringSet is vendored from docker distribution
// https://github.com/docker/distribution/blob/b6e0cfbdaa1ddc3a17c95142c7bf6e42c5567370/registry/auth/token/stringset.go
type stringSet map[string]struct{}

// NewStringSet creates a new StringSet with the given strings.
func newStringSet(keys ...string) stringSet {
	ss := make(stringSet, len(keys))
	ss.add(keys...)
	return ss
}

// Add inserts the given keys into this StringSet.
func (ss stringSet) add(keys ...string) {
	for _, key := range keys {
		ss[key] = struct{}{}
	}
}

// Contains returns whether the given key is in this StringSet.
func (ss stringSet) contains(key string) bool {
	_, ok := ss[key]
	return ok
}

// Keys returns a slice of all keys in this StringSet.
func (ss stringSet) keys() []string {
	keys := make([]string, 0, len(ss))

	for key := range ss {
		keys = append(keys, key)
	}

	return keys
}

// actionSet is a special type of stringSet also vendored from docker/distribution
// https://github.com/docker/distribution/blob/b6e0cfbdaa1ddc3a17c95142c7bf6e42c5567370/registry/auth/token/util.go
type actionSet struct {
	stringSet
}

func newActionSet(actions ...string) actionSet {
	return actionSet{newStringSet(actions...)}
}

// Contains calls StringSet.Contains() for
// either "*" or the given action string.
func (s actionSet) contains(action string) bool {
	return s.stringSet.contains("*") || s.stringSet.contains(action)
}

// accessSet maps a typed, named resource to
// a set of actions requested or authorized.
// vendored from docker/distribution
// https://github.com/docker/distribution/blob/a6bf3dd064f15598166bca2d66a9962a9555139e/registry/auth/token/accesscontroller.go
type accessSet map[registryAuth.Resource]actionSet

// newAccessSet constructs an accessSet from
// a variable number of registryAuth.Access items.
func newAccessSet(accessItems ...registryAuth.Access) accessSet {
	accessSet := make(accessSet, len(accessItems))

	for _, access := range accessItems {
		resource := registryAuth.Resource{
			Type: access.Type,
			Name: access.Name,
		}

		set, exists := accessSet[resource]
		if !exists {
			set = newActionSet()
			accessSet[resource] = set
		}

		set.add(access.Action)
	}

	return accessSet
}

// contains returns whether or not the given access is in this accessSet.
func (s accessSet) contains(access registryAuth.Access) bool {
	actionSet, ok := s[access.Resource]
	if ok {
		return actionSet.contains(access.Action)
	}

	return false
}

// scopeParam returns a collection of scopes which can
// be used for a WWW-Authenticate challenge parameter.
// See https://tools.ietf.org/html/rfc6750#section-3
func (s accessSet) scopeParam() string {
	scopes := make([]string, 0, len(s))

	for resource, actionSet := range s {
		actions := strings.Join(actionSet.keys(), ",")
		scopes = append(scopes, fmt.Sprintf("%s:%s:%s", resource.Type, resource.Name, actions))
	}

	return strings.Join(scopes, " ")
}

// authChallenge implements the auth.Challenge interface.
// https://github.com/docker/distribution/blob/a6bf3dd064f15598166bca2d66a9962a9555139e/registry/auth/token/accesscontroller.go
type authChallenge struct {
	err       error
	realm     string
	service   string
	accessSet accessSet
}

var _ registryAuth.Challenge = authChallenge{}

// Error returns the internal error string for this authChallenge.
func (ac authChallenge) Error() string {
	return ac.err.Error()
}

// Status returns the HTTP Response Status Code for this authChallenge.
func (ac authChallenge) Status() int {
	return http.StatusUnauthorized
}

// challengeParams constructs the value to be used in
// the WWW-Authenticate response challenge header.
// See https://tools.ietf.org/html/rfc6750#section-3
func (ac authChallenge) challengeParams() string {
	str := fmt.Sprintf("Bearer realm=%q,service=%q", ac.realm, ac.service)

	if scope := ac.accessSet.scopeParam(); scope != "" {
		str = fmt.Sprintf("%s,scope=%q", str, scope)
	}

	if ac.err == registryToken.ErrInvalidToken || ac.err == registryToken.ErrMalformedToken {
		str = fmt.Sprintf("%s,error=%q", str, "invalid_token")
	} else if ac.err == registryToken.ErrInsufficientScope {
		str = fmt.Sprintf("%s,error=%q", str, "insufficient_scope")
	}
	logrus.Info(str)
	return str
}

// SetChallenge sets the WWW-Authenticate value for the response.
func (ac authChallenge) SetHeaders(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", ac.challengeParams())
}
