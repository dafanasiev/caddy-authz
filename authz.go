package authz

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"net/http"
	"time"

	"github.com/casbin/casbin"
	"github.com/dafanasiev/authfile"
)

func init() {
	caddy.RegisterModule(Authorizer{})
	httpcaddyfile.RegisterHandlerDirective("authz", parseCaddyfile)
}

type Authorizer struct {
	AuthConfig struct {
		ModelPath  string
		PolicyPath string
		Realm         string
		PasswordFile string
	}

	Enforcer      *casbin.Enforcer
	PasswordCheck authfile.IAuthenticationService
}

// CaddyModule returns the Caddy module information.
func (Authorizer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.authz",
		New: func() caddy.Module { return new(Authorizer) },
	}
}

// Provision implements caddy.Provisioner.
func (a *Authorizer) Provision(ctx caddy.Context) error {
	filebackend, err := authfile.NewROFileBackend(a.AuthConfig.PasswordFile, 0600, time.Second*5)
	if err != nil {
		return err
	}
	authProvider := authfile.NewInMemoryService(filebackend, time.Second)
	authProvider.Update()

	e, err := casbin.NewEnforcerSafe(a.AuthConfig.ModelPath, a.AuthConfig.PolicyPath)
	if err != nil {
		return err
	}
	a.Enforcer = e

	return nil
}

// Validate implements caddy.Validator.
func (a *Authorizer) Validate() error {
	if a.Enforcer == nil {
		return fmt.Errorf("no Enforcer")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (a Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	switch a.CheckPermission(r) {
	case AccessDenied:
		w.WriteHeader(403)
		return nil
	case AccessAllowed:
		return next.ServeHTTP(w, r)
	default:
		w.Header().Set("WWW-Authenticate", "Basic realm=\""+a.AuthConfig.Realm+"\"")
		return nil
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (a *Authorizer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		a.AuthConfig.ModelPath = d.Val()
		if !d.NextArg() {
			return d.ArgErr()
		}
		a.AuthConfig.PolicyPath = d.Val()

		if !d.NextArg() {
			return d.ArgErr()
		}
		a.AuthConfig.Realm = d.Val()

		if !d.NextArg() {
			return d.ArgErr()
		}
		a.AuthConfig.PasswordFile = d.Val()
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Authorizer.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Authorizer
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// getUserName gets the user name from the request.
// Currently, only HTTP basic authentication is supported
func (a *Authorizer) getUserName(r *http.Request) string {
	username, _, _ := r.BasicAuth()
	return username
}

// checkEnforce verifies if the user has access to the resource. If no
// username is given, the check will be against "nobody" only.
func (a *Authorizer) checkEnforce(user, path, method string) (int, bool) {
	if user != "" {
		if a.Enforcer.Enforce(user, path, method) {
			return IdentifiedAccess, true
		}
	}
	if a.Enforcer.Enforce("nobody", path, method) {
		if user != "" {
			return IdentifiedAccess, true
		}
		return AnonymousAccess, true
	}
	return 0, false
}

const (
	// MustAuthenticate is returned if authentication is required.
	MustAuthenticate = 0
	// AccessAllowed is returned if the user has access to the resource.
	AccessAllowed = 1
	// AccessDenied is returned if the user has no access to the resource.
	AccessDenied = 2
	// AnonymousAccess is returned if the access is authorized for anonymous access.
	AnonymousAccess = 1
	// IdentifiedAccess is returned if the access is authorized for an identified user.
	IdentifiedAccess = 2
)

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *Authorizer) CheckPermission(r *http.Request) int {
	var goodAuthentication bool
	user, password, authenticated := r.BasicAuth()
	if authenticated {
		if err := a.PasswordCheck.Authenticate(user, password); err != nil {
			goodAuthentication = false
		} else {
			goodAuthentication = true
		}
	}

	method := r.Method
	path := r.URL.Path

	authorizeLevel, authorized := a.checkEnforce(user, path, method)
	if authorized {
		switch authorizeLevel {
		case AnonymousAccess:
			return AccessAllowed
		case IdentifiedAccess:
			if !authenticated || !goodAuthentication {
				return MustAuthenticate
			}
			if authenticated && goodAuthentication {
				return AccessAllowed
			}
		}
	} else if !authenticated {
		return MustAuthenticate
	}
	return AccessDenied
}
