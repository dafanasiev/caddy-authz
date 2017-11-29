package authz

import (
	"net/http"
	"time"

	"github.com/JonathanLogan/authfile"
	"github.com/casbin/casbin"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Authorizer is a middleware for filtering clients based on their ip or country's ISO code.
type Authorizer struct {
	Next          httpserver.Handler
	Enforcer      *casbin.Enforcer
	Realm         string
	PasswordCheck authfile.IAuthenticationService
}

// Init initializes the plugin
func init() {
	caddy.RegisterPlugin("authz", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

// GetConfig gets the config path that corresponds to c.
func GetConfig(c *caddy.Controller) (string, string, string, string, error) {
	var modelPath, policyPath, realm, passwordFile string
	if c.Next() { // skip the directive name
		if !c.NextArg() { // expect at least one value
			return "", "", "", "", c.ArgErr() // otherwise it's an error
		}
		modelPath = c.Val() // use the value

		if !c.NextArg() { // expect at least one value
			return "", "", "", "", c.ArgErr() // otherwise it's an error
		}
		policyPath = c.Val() // use the value
		if !c.NextArg() {    // expect at least one value
			return "", "", "", "", c.ArgErr() // otherwise it's an error
		}
		realm = c.Val()   // use the value
		if !c.NextArg() { // expect at least one value
			return "", "", "", "", c.ArgErr() // otherwise it's an error
		}
		passwordFile = c.Val() // use the value
	} else {
		return "", "", "", "", c.ArgErr() // otherwise it's an error
	}
	return modelPath, policyPath, realm, passwordFile, nil
}

// Setup parses the Casbin configuration and returns the middleware handler.
func Setup(c *caddy.Controller) error {
	modelPath, policyPath, realm, passwordFile, err := GetConfig(c)

	if err != nil {
		return err
	}

	filebackend, err := authfile.NewFileBackend(passwordFile, 0600, time.Second*5)
	if err != nil {
		return err
	}
	authProvider := authfile.NewInMemoryService(filebackend, time.Second)
	authProvider.Update()

	e, err := casbin.NewEnforcerSafe(modelPath, policyPath)
	if err != nil {
		return err
	}

	// Create new middleware
	newMiddleWare := func(next httpserver.Handler) httpserver.Handler {
		return &Authorizer{
			Next:          next,
			Enforcer:      e,
			Realm:         realm,
			PasswordCheck: authProvider,
		}
	}
	// Add middleware
	cfg := httpserver.GetConfig(c)
	cfg.AddMiddleware(newMiddleWare)

	return nil
}

// ServeHTTP serves the request.
func (a Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	switch a.CheckPermission(r) {
	case AccessDenied:
		w.WriteHeader(403)
		return http.StatusForbidden, nil
	case AccessAllowed:
		return a.Next.ServeHTTP(w, r)
	default:
		w.Header().Set("WWW-Authenticate", "Basic realm=\""+a.Realm+"\"") // ToDo set realm
		return http.StatusUnauthorized, nil
	}
	return http.StatusUnauthorized, nil
}

// GetUserName gets the user name from the request.
// Currently, only HTTP basic authentication is supported
func (a *Authorizer) GetUserName(r *http.Request) string {
	username, _, _ := r.BasicAuth()
	return username
}

// CheckEnforce verifies if the user has access to the resource. If no
// username is given, the check will be against "nobody" only.
func (a *Authorizer) CheckEnforce(user, path, method string) (int, bool) {
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

	authorizeLevel, authorized := a.CheckEnforce(user, path, method)
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
