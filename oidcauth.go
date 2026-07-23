// Package oidcauth provides OIDC login for Go web apps using only
// net/http. It is a thin wrapper over github.com/coreos/go-oidc/v3 and
// golang.org/x/oauth2 that handles the authorization-code flow with PKCE
// (S256), state and nonce validation, and a signed session cookie.
//
// It targets any conformant OIDC issuer; nothing in this package is
// specific to a particular identity provider.
//
// # Identity rule: key on sub, never on email
//
// Apps must key user accounts on the ID token's `sub` claim, never on
// email. OIDC guarantees `sub` is unique per issuer and never reassigned;
// it guarantees nothing about email. Emails are mutable and reassignable.
// Store email alongside `sub` for display and migration, but only `sub`
// is the key. See the README for the full rationale.
package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config holds the settings required to construct an [Auth]. Use
// [FromEnv] to populate it from AUTH_* environment variables.
type Config struct {
	// Issuer is the OIDC issuer URL, e.g. "https://auth.example.com".
	// Discovery and JWKS URLs derive from it.
	Issuer string
	// ClientID is the OAuth2 client id; it is also the expected `aud`
	// of every ID token this Auth accepts.
	ClientID string
	// ClientSecret is the OAuth2 client secret.
	ClientSecret string
	// RedirectURL is the app's absolute OAuth callback URL, e.g.
	// "https://app.example.com/auth/callback". Its path is where
	// [Auth.CallbackHandler] must be mounted ([Auth.Mount] does this).
	// A "http://" scheme (local dev) disables the cookie Secure flag.
	RedirectURL string
	// CookieSecret is the HMAC key for state and session cookies.
	// It must be at least 32 bytes, e.g. from `openssl rand -hex 32`.
	CookieSecret string
}

// FromEnv builds a Config from the environment:
//
//	AUTH_ISSUER, AUTH_CLIENT_ID, AUTH_CLIENT_SECRET,
//	AUTH_REDIRECT_URL, AUTH_COOKIE_SECRET
//
// It returns an error naming every missing variable.
func FromEnv() (Config, error) {
	cfg := Config{
		Issuer:       os.Getenv("AUTH_ISSUER"),
		ClientID:     os.Getenv("AUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("AUTH_REDIRECT_URL"),
		CookieSecret: os.Getenv("AUTH_COOKIE_SECRET"),
	}
	var missing []string
	for _, v := range []struct{ name, val string }{
		{"AUTH_ISSUER", cfg.Issuer},
		{"AUTH_CLIENT_ID", cfg.ClientID},
		{"AUTH_CLIENT_SECRET", cfg.ClientSecret},
		{"AUTH_REDIRECT_URL", cfg.RedirectURL},
		{"AUTH_COOKIE_SECRET", cfg.CookieSecret},
	} {
		if v.val == "" {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("oidcauth: missing environment variables: %s",
			strings.Join(missing, ", "))
	}
	return cfg, nil
}

// User holds the verified identity claims stored in the app session.
type User struct {
	// Sub is the issuer-unique, never-reassigned user identifier.
	// It is the ONLY claim apps may key accounts on.
	Sub string `json:"sub"`
	// Email is for display and migration only — never an account key.
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// Auth performs the OIDC authorization-code flow and manages the app
// session cookie. Construct with [New] or [NewFromEnv]; mount its
// handlers with [Auth.Mount] or individually.
type Auth struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier

	cookieSecret  []byte
	secureCookies bool

	sessionCookieName string
	sessionTTL        time.Duration

	loginPath    string
	callbackPath string
	logoutPath   string

	postLogoutRedirect string
	knownSub           func(sub string) bool
	forceConsentParams map[string]string

	now func() time.Time // test hook
}

// Option customizes an [Auth].
type Option func(*Auth) error

// WithSessionTTL sets the app session lifetime (default 24h).
func WithSessionTTL(d time.Duration) Option {
	return func(a *Auth) error {
		if d <= 0 {
			return errors.New("oidcauth: session TTL must be positive")
		}
		a.sessionTTL = d
		return nil
	}
}

// WithCookieName sets the session cookie name (default "_oidcauth").
// The state cookie is named "<name>_state".
func WithCookieName(name string) Option {
	return func(a *Auth) error {
		if name == "" {
			return errors.New("oidcauth: cookie name must not be empty")
		}
		a.sessionCookieName = name
		return nil
	}
}

// WithLoginPath sets where [Auth.LoginHandler] is mounted (default
// "/auth/login"). [Auth.RequireAuth] redirects unauthenticated GET
// requests here.
func WithLoginPath(p string) Option {
	return func(a *Auth) error {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("oidcauth: login path %q must start with /", p)
		}
		a.loginPath = p
		return nil
	}
}

// WithLogoutPath sets where [Auth.LogoutHandler] is mounted (default
// "/auth/logout").
func WithLogoutPath(p string) Option {
	return func(a *Auth) error {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("oidcauth: logout path %q must start with /", p)
		}
		a.logoutPath = p
		return nil
	}
}

// WithPostLogoutRedirect sets where [Auth.LogoutHandler] redirects
// after clearing the session (default "/").
func WithPostLogoutRedirect(p string) Option {
	return func(a *Auth) error {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("oidcauth: post-logout redirect %q must start with /", p)
		}
		a.postLogoutRedirect = p
		return nil
	}
}

// ForceApprovalIfNewUser makes the callback restart the auth request
// with a forced consent prompt when known(sub) reports an unfamiliar
// user, so each user sees an explicit consent screen exactly once per
// app. known must be fast and non-blocking (e.g. a map or indexed DB
// lookup). The restart happens at most once per login attempt. The
// parameters sent on the restart are issuer-neutral by default; see
// [WithForceConsentParams].
func ForceApprovalIfNewUser(known func(sub string) bool) Option {
	return func(a *Auth) error {
		if known == nil {
			return errors.New("oidcauth: ForceApprovalIfNewUser requires a non-nil func")
		}
		a.knownSub = known
		return nil
	}
}

// WithForceConsentParams replaces the extra authorization-request
// parameters sent when [ForceApprovalIfNewUser] triggers a consent
// restart. The default sends both the standard OIDC `prompt=consent`
// and the pre-OIDC `approval_prompt=force`: conformant issuers must
// ignore parameters they don't recognize (RFC 6749 §3.1), so each
// issuer honors the one it knows — no issuer-specific configuration
// needed. Override only for an issuer that rejects the combination
// (Google, used directly, errors on conflicting prompt parameters):
//
//	oidcauth.WithForceConsentParams(map[string]string{"prompt": "consent"})
func WithForceConsentParams(params map[string]string) Option {
	return func(a *Auth) error {
		if len(params) == 0 {
			return errors.New("oidcauth: WithForceConsentParams requires at least one parameter")
		}
		a.forceConsentParams = maps.Clone(params)
		return nil
	}
}

// NewFromEnv is shorthand for [FromEnv] followed by [New].
func NewFromEnv(ctx context.Context, opts ...Option) (*Auth, error) {
	cfg, err := FromEnv()
	if err != nil {
		return nil, err
	}
	return New(ctx, cfg, opts...)
}

// New validates cfg, performs OIDC discovery against cfg.Issuer, and
// returns an Auth ready to serve. The context governs discovery and is
// retained for background JWKS refreshes.
func New(ctx context.Context, cfg Config, opts ...Option) (*Auth, error) {
	if len(cfg.CookieSecret) < 32 {
		return nil, fmt.Errorf("oidcauth: cookie secret must be at least 32 bytes, got %d",
			len(cfg.CookieSecret))
	}
	callbackPath, secure, err := parseRedirectURL(cfg.RedirectURL)
	if err != nil {
		return nil, err
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: OIDC discovery for %s: %w", cfg.Issuer, err)
	}

	a := &Auth{
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier:           provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		cookieSecret:       []byte(cfg.CookieSecret),
		secureCookies:      secure,
		sessionCookieName:  "_oidcauth",
		sessionTTL:         24 * time.Hour,
		loginPath:          "/auth/login",
		callbackPath:       callbackPath,
		logoutPath:         "/auth/logout",
		postLogoutRedirect: "/",
		forceConsentParams: map[string]string{
			"prompt":          "consent", // standard OIDC
			"approval_prompt": "force",   // pre-OIDC; e.g. Dex <= v2.45.1 honors only this
		},
		now: time.Now,
	}
	for _, opt := range opts {
		if err := opt(a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func parseRedirectURL(raw string) (callbackPath string, secure bool, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("oidcauth: invalid redirect URL %q: %w", raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false, fmt.Errorf("oidcauth: redirect URL %q must be absolute http(s)", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", false, fmt.Errorf("oidcauth: redirect URL %q must not contain a query or fragment", raw)
	}
	if u.Path == "" || u.Path == "/" {
		return "", false, fmt.Errorf("oidcauth: redirect URL %q needs a non-root path (e.g. /auth/callback)", raw)
	}
	// The handler mounts at this path, but the issuer gets the raw
	// cfg.RedirectURL as redirect_uri. Cleaning a non-canonical path
	// here (trailing slash, //, ..) would desync the two: the issuer
	// would redirect to the raw path while the handler sits at the
	// cleaned one, and the callback would silently never fire. Reject
	// instead, consistent with the query/fragment/root checks above.
	if clean := path.Clean(u.Path); clean != u.Path {
		return "", false, fmt.Errorf("oidcauth: redirect URL %q has a non-canonical path; use %q", raw, clean)
	}
	return u.Path, u.Scheme == "https", nil
}

// LoginPath returns where [Auth.LoginHandler] expects to be mounted.
func (a *Auth) LoginPath() string { return a.loginPath }

// CallbackPath returns the path component of the redirect URL, where
// [Auth.CallbackHandler] must be mounted.
func (a *Auth) CallbackPath() string { return a.callbackPath }

// LogoutPath returns where [Auth.LogoutHandler] expects to be mounted.
func (a *Auth) LogoutPath() string { return a.logoutPath }

// Mount registers the login, callback, and logout handlers on mux at
// their configured paths.
func (a *Auth) Mount(mux *http.ServeMux) {
	mux.Handle(a.loginPath, a.LoginHandler())
	mux.Handle(a.callbackPath, a.CallbackHandler())
	mux.Handle(a.logoutPath, a.LogoutHandler())
}
