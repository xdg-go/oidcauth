// Package oidcauth provides OIDC login for Go web apps using only
// net/http: authorization-code flow with PKCE, state and nonce
// validation, and the verified identity in an HMAC-signed cookie. It
// wraps github.com/coreos/go-oidc/v3 and golang.org/x/oauth2 and works
// with any conformant issuer.
//
// # Identity
//
// Key accounts on (iss, sub). Never key on email, and never link
// accounts because emails match.
//
// sub is unique and permanent within an issuer. Email is none of those:
// users change it, providers recycle it, and some issuers emit it
// unverified or attacker-chosen (the "nOAuth" attack). A second
// connector can present the same email under a different sub. Store
// email beside the pair for display and recovery; let it suggest a
// link only when the user proves it, e.g. by a verification challenge.
//
// sub is opaque and stable only within an issuer. Replacing the issuer
// implementation, or how it authenticates upstream, can change every
// sub behind an unchanged URL. Before such a migration, store a durable
// upstream identity (via [WithExtraClaims]) or accept email as the
// mapping key under the rule above.
//
// # Middleware
//
// Wrap the whole tree in [Auth.Authenticate]; gate routes with
// [Auth.RequireAuth]. Authenticate verifies once per request, never
// rejects, and renews the cookie. RequireAuth reuses that result, or
// verifies inline when no Authenticate ran. Either way the cookie is
// checked exactly once.
//
// Only Authenticate renews. Mount at least one in the user's normal
// browsing path, or sessions expire a full lifetime after login no
// matter how active the user is. Nesting cannot turn renewal off: the
// strongest mount covering a route decides, and a response never
// carries two session cookies.
//
// One *Auth per process; see [UserFromContext].
//
// # Session lifetime
//
// Two deadlines, both checked on every verify; the first one reached
// ends the session.
//
//   - [WithSessionLifetime] (90d) counts from the last cookie write and
//     slides: a request within [WithSessionRenewWindow] (45d) of expiry
//     re-issues the cookie.
//   - [WithSessionMaxLifetime] (365d) counts from first login for a cookie
//     and never moves. Renewal will not extend a session past max lifetime.
//
// Renewal extends the cookie's expiration; it does not re-authenticate.
// Claims freeze at login, so a user disabled at the provider keeps a
// valid session until the max lifetime. A stolen cookie renews on the
// thief's requests just as it would on the user's, so the max lifetime
// is the only bound this package puts on it. Ending a session sooner
// is the app's job; see "Revoking sessions" below.
//
// [New] requires renew window <= lifetime <= max lifetime and fails
// rather than substituting defaults.
//
// # Revoking sessions
//
// [WithRevokedBefore] asks the app, on every verified session, for
// that user's revocation cutoff: the instant before which their
// sessions are void. A session issued before the cutoff is rejected.
// To log a user out everywhere, store time.Now() for that user when
// revoking and return it from the lookup.
//
// Store now, never the current cookie's issue time. A stolen cookie
// carries the same issue time as the user's own (see "Session
// lifetime" above), so a cutoff set there would spare the attacker
// along with the user.
//
// The lookup runs once per authenticated request, so caching the
// cutoff is the app's job. Revocation takes effect within a second
// of the stored time.
//
// This package does not recover from a panicking lookup. What the
// client sees is whatever the app's own recovery middleware does; with
// none, net/http's per-connection recovery logs the panic and closes
// the connection without writing a status, HTTP/2 resets the stream,
// and a directly invoked handler propagates the panic. Recover inside
// the lookup, or mount recovery middleware.
//
// # Cookie secret rotation
//
// To rotate: move the current CookieSecret into
// [Config.PreviousCookieSecrets], set a fresh CookieSecret, deploy.
// New cookies are signed by the new key while cookies signed by the old
// one still verify, so nobody is logged out and no in-flight login
// breaks.
//
// # Caching
//
// Set-Cookie does not stop a shared cache from storing and replaying a
// response (RFC 9111 §7.3; CloudFront does). So any response this
// package writes a cookie onto gets Cache-Control: private, no-store; a
// verified session without a write gets private; anonymous responses
// are untouched. All three get Vary: Cookie.
//
// The headers are set before your handler runs, and your handler can
// overwrite them. The package will not wrap http.ResponseWriter to
// stop that (it breaks io.ReaderFrom and http.Flusher). If you set
// Cache-Control on a route that can carry a session, set
// "private, no-store".
//
// A page that renders differently for logged-in and anonymous users
// must not be stored by a shared cache, whichever middleware it sits
// behind. Its anonymous rendering gets Vary: Cookie but no
// Cache-Control, so nothing but Vary keeps a CDN from serving that
// copy to a logged-in user -- and real CDNs do not honor Vary on
// Cookie reliably. Set "private, no-store" yourself on any route whose
// body depends on login state.
//
// Before writing the session cookie the package drops any queued
// Set-Cookie of the same name, so the last writer wins. Matching
// ignores Path and Domain; a handler clearing a legacy Domain= copy of
// the same name in the same response loses that write.
//
// # Issuer availability
//
// [New] does no I/O. Discovery runs on the first login and retries
// with a cooldown. Session verification uses CookieSecret, not the
// issuer's keys, so existing sessions survive an issuer outage; new
// logins return 503 until discovery succeeds. [Auth.Connect] makes
// startup fail instead.
//
// # Logout
//
// [Auth.LogoutHandler] is POST-only and clears only the app cookie; the
// issuer's session is untouched. [Auth.ClearSession] does the same from
// inside your own handler.
package oidcauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
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
	// PreviousCookieSecrets are retired HMAC keys that still verify
	// state and session cookies but never sign new ones.
	PreviousCookieSecrets []string
}

// FromEnv builds a Config from the environment:
//
//	AUTH_ISSUER, AUTH_CLIENT_ID, AUTH_CLIENT_SECRET,
//	AUTH_REDIRECT_URL, AUTH_COOKIE_SECRET
//
//	AUTH_COOKIE_SECRET_PREVIOUS is optional: a comma-separated list of
//	retired secrets that still verify cookies.
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
	if prev := os.Getenv("AUTH_COOKIE_SECRET_PREVIOUS"); prev != "" {
		for s := range strings.SplitSeq(prev, ",") {
			cfg.PreviousCookieSecrets = append(cfg.PreviousCookieSecrets, strings.TrimSpace(s))
		}
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
	// Issuer is the verified `iss` of the ID token. Together with Sub
	// it forms the account key: sub is unique only within an issuer.
	Issuer string `json:"iss"`
	// Sub is the issuer-unique, never-reassigned user identifier.
	// (Issuer, Sub) is the ONLY pair apps may key accounts on.
	Sub string `json:"sub"`
	// Email is for display and recovery only — never an account key,
	// and never a basis for automatically linking accounts.
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	// Extra holds the raw JSON of claims requested via
	// [WithExtraClaims], keyed by claim name; absent claims have no
	// entry. Unmarshal into app types as needed.
	Extra map[string]json.RawMessage `json:"extra,omitempty"`
}

// Auth performs the OIDC authorization-code flow and manages the app
// session cookie. Construct with [New] or [NewFromEnv]; mount its
// handlers with [Auth.Mount] or individually.
type Auth struct {
	oauth      oauth2.Config
	issuer     string
	httpClient *http.Client

	// Lazy discovery state. verifier doubles as the "discovered"
	// flag: it is nil until discovery succeeds and immutable after.
	// sf collapses concurrent discovery attempts into one flight,
	// and after a failed attempt callers fail fast with discErr
	// until discoveryCooldown elapses.
	sf          singleflight.Group
	mu          sync.Mutex
	verifier    *oidc.IDTokenVerifier
	discErr     error     // last failed attempt's error
	lastAttempt time.Time // when discErr was recorded

	signingKey    []byte
	verifyKeys    [][]byte
	secureCookies bool

	sessionCookieName  string
	sessionLifetime    time.Duration
	renewWindow        time.Duration
	maxSessionLifetime time.Duration

	loginPath    string
	callbackPath string
	logoutPath   string

	postLogoutRedirect string
	knownSub           func(iss, sub string) bool
	forceConsentParams map[string]string
	extraClaims        []string

	revokedBefore func(ctx context.Context, u User) (time.Time, error)

	logger *slog.Logger

	now func() time.Time // test hook
}

// Option customizes an [Auth].
type Option func(*Auth) error

// checkSessionDuration rejects a session duration the cookie payload
// cannot represent. Expiry and IssuedAt are both stored in whole
// seconds, so a sub-second remainder is silently truncated away: a
// 100ms lifetime would mint a cookie already expired on arrival, and
// any fractional value shortens by an amount that depends on the
// current wall-clock offset.
func checkSessionDuration(name string, d time.Duration) error {
	if d < time.Second {
		return fmt.Errorf("oidcauth: %s must be at least 1s, got %v", name, d)
	}
	if d%time.Second != 0 {
		return fmt.Errorf("oidcauth: %s must be a whole number of seconds, got %v", name, d)
	}
	return nil
}

// WithSessionLifetime sets how long a session cookie lives from each
// write (default 90 days). The deadline slides: [Auth.Authenticate]
// renews on the first request arriving within the renew window before
// the expiry (see [WithSessionRenewWindow], default 45 days). So an
// active user keeps moving the deadline, while an idle user's session
// ends between one renew window and one full lifetime after their last
// request -- sooner if the max lifetime cuts it short.
//
// Must be a whole number of seconds of at least 1s, at least the
// renew window, and no longer than [WithSessionMaxLifetime]. Both bounds apply
// at their defaults, so a lifetime above 365 days or below 45 days fails
// construction unless the corresponding option is set too.
func WithSessionLifetime(d time.Duration) Option {
	return func(a *Auth) error {
		if err := checkSessionDuration("session lifetime", d); err != nil {
			return err
		}
		a.sessionLifetime = d
		return nil
	}
}

// WithSessionRenewWindow sets how long before a session cookie's expiry
// an arriving request triggers renewal (default 45 days). While a
// request lands outside the window [Auth.Authenticate] leaves the
// cookie alone; the first request inside it re-issues the cookie with
// a fresh lifetime. At the defaults (90-day lifetime, 45-day window)
// renewal fires 45 days after the cookie was written.
//
// Setting the window equal to the session lifetime renews on every
// request, which is the true last-request idle timeout: the deadline
// always sits exactly one lifetime after the user's most recent
// request. Until the session nears its max lifetime (see
// [WithSessionMaxLifetime]), it costs a Set-Cookie on every
// authenticated response, and per the cache rules every such response
// is marked Cache-Control: private, no-store.
//
// Must be a whole number of seconds of at least 1s and must not
// exceed the session lifetime.
func WithSessionRenewWindow(d time.Duration) Option {
	return func(a *Auth) error {
		if err := checkSessionDuration("session renew window", d); err != nil {
			return err
		}
		a.renewWindow = d
		return nil
	}
}

// WithSessionMaxLifetime sets how long a session may live from the
// original login (default 365 days). This deadline never moves:
// renewal preserves the original issue time, so no amount of activity
// pushes a session past it. It is enforced on every verify, so a
// cookie still inside its own lifetime is rejected once it reaches the
// maximum, exactly as an expired one is. A renewal's expiry is clamped
// to this deadline; once pinned there, later renewals compute the same
// expiry and skip the rewrite, so the tail costs at most one extra
// cookie write and never pushes a session past the max. The deadline is computed from the issue time
// stored in each cookie, so lowering it applies to sessions already
// minted. Must be a whole number of seconds of at least 1s and must
// not be shorter than the session lifetime.
func WithSessionMaxLifetime(d time.Duration) Option {
	return func(a *Auth) error {
		if err := checkSessionDuration("session max lifetime", d); err != nil {
			return err
		}
		a.maxSessionLifetime = d
		return nil
	}
}

// WithRevokedBefore sets an app-supplied lookup of the instant before
// which this user's sessions are void. It runs on every session
// verification, after the cookie's signature, issue time, expiry, and
// max lifetime have all passed, so it must be fast and
// concurrency-safe.
//
// The returned time has three outcomes. The zero time revokes nothing,
// so a store miss needs no app-side branch. A non-zero time rejects a
// session issued before it, exactly as an expired cookie is rejected:
// same response, and no renewed cookie. A non-nil error reports that
// the lookup could not answer. That is an operational failure, not an
// authorization decision: [Auth.RequireAuth] answers 503, bare
// [Auth.Authenticate] treats the request as anonymous, and nothing is
// renewed. The failure is logged at warn, or at debug when the request
// context is already done, because a client that went away is
// ordinary traffic.
//
// A non-zero time returned alongside a non-nil error is ignored: the
// error wins, and the lookup counts as a failure.
//
// A cutoff in the future is clamped to now on the instance serving
// the request. A misconfigured store therefore cannot revoke the
// session a fresh login is about to mint, which would lock the user
// out of that instance. The clamp is against one server's clock, so
// it says nothing about skew between instances: a session minted on a
// slow instance can still be rejected by a faster one until the skew
// elapses.
//
// There is no fail-open switch. An app that would rather let requests
// through during its own store outage returns the zero time from its
// error path; one that would rather shut them out returns the error.
//
// Treat the User as read-only. Its Extra map is the same map handlers
// read from the request context, shared rather than copied, so writing
// to it races with them.
//
// ctx is the request's context: a lookup doing I/O should pass it down
// and honor cancellation. The error's text is logged verbatim, so keep
// identifiers, SQL, and anything else sensitive out of it. A nil fn is
// a config error.
func WithRevokedBefore(fn func(ctx context.Context, u User) (time.Time, error)) Option {
	return func(a *Auth) error {
		if fn == nil {
			return errors.New("oidcauth: revocation lookup must not be nil")
		}
		a.revokedBefore = fn
		return nil
	}
}

// WithLogger sets the logger used for diagnostic messages, such as
// the reason a session cookie was rejected (logged at debug level).
// The default discards all output. A nil logger is a config error.
func WithLogger(l *slog.Logger) Option {
	return func(a *Auth) error {
		if l == nil {
			return errors.New("oidcauth: logger must not be nil")
		}
		a.logger = l
		return nil
	}
}

// WithCookieName sets the session cookie name (default "_oidcauth").
// The state cookie is named "<name>_state". Over a secure connection
// both go on the wire with the "__Host-" prefix, as "__Host-<name>"
// and "__Host-<name>_state"; plain-http dev, where the prefix would
// not be honored, uses the bare names. Pass the name without the
// prefix: supplying it is rejected rather than doubled.
func WithCookieName(name string) Option {
	return func(a *Auth) error {
		if name == "" {
			return errors.New("oidcauth: cookie name must not be empty")
		}
		// Browsers apply the prefix rules case-insensitively
		// (rfc6265bis 5.7), so match that way too: a bare "__host-sess"
		// under http dev would be silently dropped by the browser, with
		// no server-side error to explain the login loop. "__Secure-"
		// carries its own browser rule and is not this package's to
		// hand out, so reject it on the same grounds.
		for _, prefix := range []string{hostCookiePrefix, secureCookiePrefix} {
			if len(name) >= len(prefix) && strings.EqualFold(name[:len(prefix)], prefix) {
				return fmt.Errorf("oidcauth: cookie name must not begin with %q; the %q prefix is added automatically for secure cookies", prefix, hostCookiePrefix)
			}
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
// with a forced consent prompt when known(iss, sub) reports an
// unfamiliar user, so each user sees an explicit consent screen
// exactly once per app. iss is the verified issuer of the ID token —
// constant per [Auth], but passed so known can be a store method
// keyed on the (iss, sub) account pair. known must be fast and
// non-blocking (e.g. a map or indexed DB lookup). The restart happens
// at most once per login attempt. The parameters sent on the restart
// are issuer-neutral by default; see [WithForceConsentParams].
func ForceApprovalIfNewUser(known func(iss, sub string) bool) Option {
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

// WithExtraClaims names additional ID-token claims to carry into the
// session, exposed raw on [User].Extra. Use it when the issuer emits
// claims beyond the standard profile set that apps need at login —
// e.g. upstream-identity claims a broker adds for account-migration
// durability. Claims absent from a token are simply omitted. Keep the
// list small: the session rides in a cookie.
func WithExtraClaims(names ...string) Option {
	return func(a *Auth) error {
		if len(names) == 0 {
			return errors.New("oidcauth: WithExtraClaims requires at least one claim name")
		}
		a.extraClaims = slices.Clone(names)
		return nil
	}
}

// httpTimeout bounds every network call this package makes —
// discovery, JWKS fetches during ID-token verification, and the token
// exchange. The zero-timeout http.DefaultClient would let a hung
// issuer pin a request (or process shutdown) indefinitely.
const httpTimeout = 10 * time.Second

// discoveryCooldown is how long after a failed discovery attempt
// callers fail fast with the cached error instead of retrying, so a
// hard-down issuer is not re-probed once per request.
const discoveryCooldown = 2 * time.Second

// defaultRenewWindow is how long before expiry an arriving request
// renews the session cookie unless [WithSessionRenewWindow] says
// otherwise.
const defaultRenewWindow = 45 * 24 * time.Hour

// NewFromEnv is shorthand for [FromEnv] followed by [New].
func NewFromEnv(opts ...Option) (*Auth, error) {
	cfg, err := FromEnv()
	if err != nil {
		return nil, err
	}
	return New(cfg, opts...)
}

// New validates cfg and returns an [Auth]. It performs no I/O: OIDC
// discovery against cfg.Issuer happens on demand from the login and
// callback handlers, so an app can start — and serve existing
// sessions, which are verified against cfg.CookieSecret rather than
// the issuer's keys — while the issuer is unreachable. Apps that want
// startup to fail on an unreachable or misconfigured issuer call
// [Auth.Connect] after New.
func New(cfg Config, opts ...Option) (*Auth, error) {
	if len(cfg.CookieSecret) < 32 {
		return nil, fmt.Errorf("oidcauth: cookie secret must be at least 32 bytes, got %d",
			len(cfg.CookieSecret))
	}
	verifyKeys := [][]byte{[]byte(cfg.CookieSecret)}
	for i, prev := range cfg.PreviousCookieSecrets {
		if prev == "" {
			return nil, fmt.Errorf("oidcauth: previous cookie secrets contain an empty entry; " +
				"check AUTH_COOKIE_SECRET_PREVIOUS for a stray comma")
		}
		if len(prev) < 32 {
			return nil, fmt.Errorf("oidcauth: previous cookie secret %d must be at least 32 bytes, got %d",
				i, len(prev))
		}
		verifyKeys = append(verifyKeys, []byte(prev))
	}
	callbackPath, secure, err := parseRedirectURL(cfg.RedirectURL)
	if err != nil {
		return nil, err
	}

	a := &Auth{
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		issuer:             cfg.Issuer,
		httpClient:         &http.Client{Timeout: httpTimeout},
		signingKey:         []byte(cfg.CookieSecret),
		verifyKeys:         verifyKeys,
		secureCookies:      secure,
		sessionCookieName:  "_oidcauth",
		sessionLifetime:    90 * 24 * time.Hour,
		renewWindow:        defaultRenewWindow,
		maxSessionLifetime: 365 * 24 * time.Hour,
		loginPath:          "/auth/login",
		callbackPath:       callbackPath,
		logoutPath:         "/auth/logout",
		postLogoutRedirect: "/",
		forceConsentParams: map[string]string{
			"prompt":          "consent", // standard OIDC
			"approval_prompt": "force",   // pre-OIDC; e.g. Dex <= v2.45.1 honors only this
		},
		logger: slog.New(slog.DiscardHandler),
		now:    time.Now,
	}
	for _, opt := range opts {
		if err := opt(a); err != nil {
			return nil, err
		}
	}
	// Cross-field checks: options may arrive in any order, so the
	// relative ordering renew window <= session lifetime <= max
	// lifetime can only be judged once all of them have been applied.
	if a.renewWindow > a.sessionLifetime {
		return nil, fmt.Errorf("oidcauth: session renew window (%v) must not exceed the session lifetime (%v); set WithSessionRenewWindow when shortening the session lifetime",
			a.renewWindow, a.sessionLifetime)
	}
	if a.maxSessionLifetime < a.sessionLifetime {
		return nil, fmt.Errorf("oidcauth: session max lifetime (%v) must not be shorter than the session lifetime (%v)",
			a.maxSessionLifetime, a.sessionLifetime)
	}
	return a, nil
}

// Connect performs OIDC discovery now instead of on demand, so that
// an unreachable or misconfigured issuer surfaces as a startup error
// rather than 503s at login time. It is optional and idempotent:
// handlers trigger the same discovery lazily, and once discovery has
// succeeded Connect returns nil immediately. ctx bounds only this
// call's wait; the attempt itself is bounded by the Auth's internal
// HTTP client timeout.
func (a *Auth) Connect(ctx context.Context) error {
	return a.ensureDiscovered(ctx)
}

// ensureDiscovered returns nil once OIDC discovery has succeeded,
// running it on demand. ctx bounds only this caller's wait: the
// attempt itself runs on singleflight's own goroutine with the
// internal client's timeout, so one impatient caller cannot kill an
// attempt others are waiting on. Concurrent callers share a single
// attempt, and for discoveryCooldown after a failure callers get that
// error without a new attempt.
func (a *Auth) ensureDiscovered(ctx context.Context) error {
	// The flight intentionally ignores the caller's ctx: its result
	// serves every waiter (ctx bounds only this caller's wait, in the
	// select below), and it is time-bounded by the internal client's
	// timeout, not by cancellation. DoChan's channel is buffered, so
	// abandoning it leaks nothing.
	ch := a.sf.DoChan("discover", func() (any, error) { //nolint:contextcheck,gosec // G118: detached by design; see above
		return nil, a.discover()
	})
	select {
	case res := <-ch:
		return res.Err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// discover runs one discovery attempt and records the outcome, unless prior
// attempts take precedence: prior success shortcircuits, and a recent, prior
// failure inside the cooldown window is returned without a new attempt.
//
// Invariant: verifier (with oauth.Endpoint) is write-once — set by
// whichever attempt first succeeds, immutable after. Both the check
// and the set run under mu, and the set re-checks for a winner, so
// the invariant holds even for concurrent discover calls; the
// singleflight wrapper in ensureDiscovered is an efficiency layer
// (dedupe and shared waiting), not a correctness dependency. The
// invariant is what lets handlers read verifier and oauth.Endpoint
// lock-free after ensureDiscovered: a write after their
// happens-before edge (the flight-result channel receive) would be a
// data race.
func (a *Auth) discover() error {
	a.mu.Lock()
	if a.verifier != nil {
		a.mu.Unlock()
		return nil
	}
	if a.discErr != nil && a.now().Sub(a.lastAttempt) < discoveryCooldown {
		err := a.discErr
		a.mu.Unlock()
		return err
	}
	a.mu.Unlock()

	// The ctx passed to NewProvider supplies the HTTP client for the
	// discovery call and (per go-oidc v3 internals) for future JWKS
	// fetches; it is NOT retained for cancellation — the provider's
	// RemoteKeySet is built on context.Background(), and JWKS fetch
	// cancellation rides the ctx later passed to Verify. If go-oidc
	// ever re-retains this ctx, nothing breaks: it is never canceled.
	ctx := oidc.ClientContext(context.Background(), a.httpClient)
	provider, err := oidc.NewProvider(ctx, a.issuer)

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.verifier != nil {
		// Another attempt won while this one was on the network; keep
		// the winner's result (discarding this provider) so verifier
		// is never rewritten.
		return nil
	}
	if err != nil {
		a.discErr = fmt.Errorf("oidcauth: OIDC discovery for %s: %w", a.issuer, err)
		a.lastAttempt = a.now()
		return a.discErr
	}
	a.oauth.Endpoint = provider.Endpoint()
	a.verifier = provider.Verifier(&oidc.Config{ClientID: a.oauth.ClientID})
	a.discErr = nil
	return nil
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
