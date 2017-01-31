package auth

import (
	"github.com/docker/distribution/context"
	registryAuth "github.com/docker/distribution/registry/auth"
	registryToken "github.com/docker/distribution/registry/auth/token"
)

// testingAccessController implements the auth.AccessController interface.
type TestingAccessController struct {
	Username string
	Allow    bool
}

// NewTestingAccessController creates a testingAccessController, only for use in tests
func NewTestingAccessController(username string) registryAuth.AccessController {
	return &TestingAccessController{
		Username: username,
		Allow:    true, // by default, all requests are authorized
	}
}

// Authorized handles checking whether the given request is authorized
// for actions on resources described by the given access items.
func (ac *TestingAccessController) Authorized(ctx context.Context, accessItems ...registryAuth.Access) (context.Context, error) {
	challenge := &authChallenge{
		realm:     "testing",
		service:   "testing",
		accessSet: newAccessSet(accessItems...),
	}

	if !ac.Allow {
		challenge.err = registryToken.ErrInsufficientScope
		return nil, challenge
	}

	return registryAuth.WithUser(ctx, registryAuth.UserInfo{Name: ac.Username}), nil
}
