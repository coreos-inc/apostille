package auth

import (
	"github.com/docker/distribution/context"
	registryAuth "github.com/docker/distribution/registry/auth"
	registryToken "github.com/docker/distribution/registry/auth/token"
)

// constantAccessController implements the auth.AccessController interface.
type ConstantAccessController struct {
	TUFRoot string
	Allow   bool
}

// NewConstantAccessController creates a constantAccessController, which always authenticates as a particular role
func NewConstantAccessController(tufRoot string) *ConstantAccessController {
	return &ConstantAccessController{
		TUFRoot: tufRoot,
		Allow:   true, // by default, all requests are authorized
	}
}

// Authorized handles checking whether the given request is authorized
// for actions on resources described by the given access items.
func (ac *ConstantAccessController) Authorized(ctx context.Context, accessItems ...registryAuth.Access) (context.Context, error) {
	challenge := &authChallenge{
		realm:     ac.TUFRoot,
		service:   ac.TUFRoot,
		accessSet: newAccessSet(accessItems...),
	}

	if !ac.Allow {
		challenge.err = registryToken.ErrInsufficientScope
		return nil, challenge
	}
	return context.WithValue(ctx, TufRootSigner, ac.TUFRoot), nil
}
