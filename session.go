package oidcauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Signed-cookie format: base64url(payload JSON) + "." + base64url(HMAC).
// The HMAC covers "<purpose>.<base64 payload>" so a cookie signed for one
// purpose (e.g. the login-state cookie) can never be replayed as another
// (e.g. the session cookie).

const (
	purposeSession = "session"
	purposeState   = "state"

	// stateTTL bounds a login attempt: the window between hitting the
	// login handler and returning to the callback. Generous enough for
	// a first-time consent screen, short enough to limit replay.
	stateTTL = 15 * time.Minute
)

// expiredCookieTime is the Expires attribute of a deleted cookie: the
// past, so a client that ignores Max-Age still drops it.
var expiredCookieTime = time.Unix(0, 0).UTC()

// errBadCookie reports that a signed cookie was absent, malformed,
// tampered with, or expired. Every rejection reason below wraps it, so
// the package presents one external failure while logs name the
// specific cause. It stays unexported until an exported API returns it.
var errBadCookie = errors.New("oidcauth: invalid or expired cookie")

// Rejection reasons. Each wraps errBadCookie so that external
// behavior is one error, while logs can name what actually failed.
var (
	errNoCookie           = fmt.Errorf("%w: no cookie present", errBadCookie)
	errBadSignature       = fmt.Errorf("%w: bad signature", errBadCookie)
	errMalformedPayload   = fmt.Errorf("%w: malformed payload", errBadCookie)
	errExpired            = fmt.Errorf("%w: expired", errBadCookie)
	errNoIssuedAt         = fmt.Errorf("%w: no issue time", errBadCookie)
	errMaxLifetimeReached = fmt.Errorf("%w: max lifetime reached", errBadCookie)

	// errCorruptPayload is the highest-signal reason: the payload
	// carried a valid MAC yet did not decode. Nothing an outsider can
	// do produces it -- reaching it means the signing key leaked or a
	// library changed under us, so it must stay distinct from
	// errMalformedPayload, which merely means a cookie from another
	// app or a truncated value.
	errCorruptPayload = fmt.Errorf("%w: corrupt payload", errBadCookie)
)

// rejectCookie logs why a signed cookie was rejected and returns the
// reason unchanged. The log names the failure class only -- never a
// cookie value, signature, or user identity -- and stays at debug
// behind an explicit Enabled check; slog already short-circuits on
// level, so the check only saves building the ...any argument slice.
func (a *Auth) rejectCookie(purpose string, err error) error {
	if a.logger.Enabled(context.Background(), slog.LevelDebug) {
		a.logger.Debug("oidcauth: cookie rejected", "cookie", purpose, "reason", err.Error())
	}
	return err
}

// sessionPayload is the signed content of the app session cookie.
type sessionPayload struct {
	User   User      `json:"user"`
	Expiry time.Time `json:"exp"`

	// IssuedAt is the mint time as Unix SECONDS (sub-second precision
	// is truncated). It is an int64 rather than a time.Time so that an
	// absent field decodes to 0, an unambiguous "not present"
	// sentinel. A zero time.Time would instead decode from an absent
	// field as 0001-01-01T00:00:00Z, whose Unix() is a large negative
	// number.
	IssuedAt int64 `json:"iat"`
}

// statePayload is the signed content of the transient login-state
// cookie that binds one auth request to the browser that started it.
type statePayload struct {
	State          string    `json:"state"`
	Nonce          string    `json:"nonce"`
	Verifier       string    `json:"verifier"`        // PKCE code verifier
	Next           string    `json:"next"`            // post-login redirect (relative)
	ConsentRestart bool      `json:"consent_restart"` // this attempt is the one-time forced-consent restart
	Expiry         time.Time `json:"exp"`
}

func (a *Auth) sign(purpose string, payload []byte) string {
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, a.signingKey)
	mac.Write([]byte(purpose + "." + b64))
	return b64 + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *Auth) verify(purpose, value string) ([]byte, error) {
	i := -1
	for j, c := range value {
		if c == '.' {
			i = j
			break
		}
	}
	if i < 0 {
		return nil, errMalformedPayload
	}
	b64, sig := value[:i], value[i+1:]
	gotMAC, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, errMalformedPayload
	}
	matched := 0
	for _, key := range a.verifyKeys {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(purpose + "." + b64))
		matched |= subtle.ConstantTimeCompare(gotMAC, mac.Sum(nil))
	}
	if matched != 1 {
		return nil, errBadSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, errCorruptPayload
	}
	return payload, nil
}

// hostCookiePrefix marks a cookie the browser stores only when it is
// Secure, host-only (no Domain), and Path=/ (rfc6265bis 5.7).
const hostCookiePrefix = "__Host-"

// secureCookiePrefix is the weaker sibling of hostCookiePrefix
// (rfc6265bis 5.7). This package never writes it; it is named only so
// [WithCookieName] can reject a name carrying it.
const secureCookiePrefix = "__Secure-"

// sessionName is the session cookie name as it goes on the wire. The
// prefix only holds over a secure connection, so plain-http dev keeps
// the bare name.
func (a *Auth) sessionName() string {
	if a.secureCookies {
		return hostCookiePrefix + a.sessionCookieName
	}
	return a.sessionCookieName
}

func (a *Auth) stateCookieName() string { return a.sessionName() + "_state" }

func (a *Auth) setSessionCookie(w http.ResponseWriter, u User) {
	now := a.now()
	a.writeSessionCookie(w, u, now.Unix(), now.Add(a.sessionLifetime), now)
}

// writeSessionCookie signs and writes one session cookie with the
// given issue time and expiry. Renewal reuses it with the original
// IssuedAt so the max lifetime keeps counting from first login.
//
// The expiry is truncated to whole seconds so it shares one time grid
// with IssuedAt, which is Unix seconds. Without that, an expiry
// carrying sub-second precision could sit a fraction past a max
// lifetime deadline computed from IssuedAt, and renewal's "already at
// the max" guard would skip the clamping rewrite, leaving a cookie
// advertising an expiry the server would refuse to honor.
//
// now is the instant exp was computed from; Max-Age is its distance to
// exp, so the caller must not re-read the clock for it.
func (a *Auth) writeSessionCookie(w http.ResponseWriter, u User, issuedAt int64, exp, now time.Time) {
	exp = exp.Truncate(time.Second)
	// Truncate, not round: Max-Age must never outlast Expires. Floor at
	// one second while the cookie is still live, because net/http omits
	// Max-Age entirely when it is zero -- a renewal clamped to within a
	// second of the max lifetime deadline would otherwise ship with
	// Expires alone and lose the clock-skew immunity Max-Age buys.
	maxAge := int(exp.Sub(now).Truncate(time.Second) / time.Second)
	if maxAge < 1 && exp.After(now) {
		maxAge = 1
	}
	markSessionResponse(w)
	payload, _ := json.Marshal(sessionPayload{User: u, Expiry: exp, IssuedAt: issuedAt})
	a.dropPendingSessionCookie(w)
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly+SameSite always set; Secure follows the redirect-URL scheme (off only for http://localhost dev)
		Name:    a.sessionName(),
		Value:   a.sign(purposeSession, payload),
		Path:    "/",
		Expires: exp,
		// Max-Age is relative, so a skewed client clock cannot make the
		// cookie expire early or late.
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// dropPendingSessionCookie removes any Set-Cookie header already
// queued for the session cookie, so the last writer wins outright
// instead of relying on the browser to prefer the last of two
// same-name cookies. Renewal writes at middleware entry, so a handler
// that then mints or clears the session would otherwise emit two.
// Matching is by cookie name only, so a handler's own Set-Cookie
// reusing the session cookie name under a different Path or Domain is
// dropped too (see "Caching" in the package doc). Cookies under any
// other name, including the state cookie, are left alone.
func (a *Auth) dropPendingSessionCookie(w http.ResponseWriter) {
	pending := w.Header()["Set-Cookie"]
	kept := pending[:0]
	for _, v := range pending {
		if setCookieName(v) != a.sessionName() {
			kept = append(kept, v)
		}
	}
	if len(kept) == 0 {
		w.Header().Del("Set-Cookie")
		return
	}
	w.Header()["Set-Cookie"] = kept
}

// setCookieName returns the cookie name from a Set-Cookie header
// value, i.e. the part before the first "=" of the first
// semicolon-separated attribute. It returns "" if the value has no
// name=value pair.
func setCookieName(value string) string {
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = value[:i]
	}
	i := strings.IndexByte(value, '=')
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(value[:i])
}

func (a *Auth) clearSessionCookie(w http.ResponseWriter) {
	markSessionResponse(w)
	a.dropPendingSessionCookie(w)
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly+SameSite always set; Secure follows the redirect-URL scheme (off only for http://localhost dev)
		Name:     a.sessionName(),
		Value:    "",
		Path:     "/",
		Expires:  expiredCookieTime,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// sessionFromRequestAt returns the whole verified payload from the
// request's session cookie, or an error if the cookie is absent,
// tampered, expired, or past the max lifetime. The current time is
// supplied by the caller, so a caller that also has to decide about
// renewal reads the clock exactly once for the whole request. Every
// rejection reason lives here, so renewal can never act on a session
// the verify path would refuse.
func (a *Auth) sessionFromRequestAt(r *http.Request, now time.Time) (sessionPayload, error) {
	c, err := r.Cookie(a.sessionName())
	if err != nil {
		// Not logged: an absent session cookie is every anonymous
		// request, and logging it would bury the reasons that carry
		// diagnostic value.
		return sessionPayload{}, errNoCookie
	}
	payload, err := a.verify(purposeSession, c.Value)
	if err != nil {
		return sessionPayload{}, a.rejectCookie(purposeSession, err)
	}
	var s sessionPayload
	if err := json.Unmarshal(payload, &s); err != nil {
		return sessionPayload{}, a.rejectCookie(purposeSession, errCorruptPayload)
	}
	// Fail closed: a payload minted before IssuedAt existed (or with
	// the field stripped) decodes to 0 and gets no partial trust. A
	// negative value is equally rejected: it is unreachable while the
	// field is HMAC-covered and only ever set from now.Unix(), but an
	// max-lifetime check computed from it would otherwise never
	// expire.
	if s.IssuedAt <= 0 {
		return sessionPayload{}, a.rejectCookie(purposeSession, errNoIssuedAt)
	}
	if !now.Before(s.Expiry) {
		return sessionPayload{}, a.rejectCookie(purposeSession, errExpired)
	}
	// The max lifetime is enforced on every verify, renewing or not,
	// so a cookie still inside its own session lifetime dies at the
	// max.
	if !now.Before(a.maxLifetimeDeadline(s)) {
		return sessionPayload{}, a.rejectCookie(purposeSession, errMaxLifetimeReached)
	}
	return s, nil
}

// maxLifetimeDeadline is the instant a session dies no matter how
// active the user is: its original issue time plus the max lifetime.
//
// An IssuedAt in the future is tolerated, never rejected. The HMAC
// proves this library minted the cookie, so a future issue time can
// only mean clock skew between instances -- an ops problem the user
// cannot fix and must not be locked out for. The deadline simply
// lands later by the skew, so such a session outlives its nominal max
// lifetime by that much. Instances are expected to run NTP, which
// keeps the skew far below any sane max lifetime.
func (a *Auth) maxLifetimeDeadline(s sessionPayload) time.Time {
	return time.Unix(s.IssuedAt, 0).Add(a.maxSessionLifetime)
}

// renewSessionCookie re-issues s when now has reached the renew window
// before its expiry (Expiry - renewWindow), preserving the
// original IssuedAt. The new expiry is clamped to the max lifetime,
// so the cookie never advertises a lifetime the server would refuse
// to honor. Callers must pass a payload that already verified, along
// with the same now that verified it.
func (a *Auth) renewSessionCookie(w http.ResponseWriter, s sessionPayload, now time.Time) {
	if now.Before(s.Expiry.Add(-a.renewWindow)) {
		return
	}
	exp := now.Add(a.sessionLifetime)
	if maxAt := a.maxLifetimeDeadline(s); exp.After(maxAt) {
		exp = maxAt
	}
	// Near the max lifetime the clamp above pins the expiry at the
	// deadline; later renewals compute that same expiry. Rewriting an
	// expiry that is not later than the current one buys nothing, so
	// skip it.
	if !exp.After(s.Expiry) {
		return
	}
	a.writeSessionCookie(w, s.User, s.IssuedAt, exp, now)
}

func (a *Auth) setStateCookie(w http.ResponseWriter, s statePayload) {
	markSessionResponse(w)
	s.Expiry = a.now().Add(stateTTL)
	payload, _ := json.Marshal(s)
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly+SameSite always set; Secure follows the redirect-URL scheme (off only for http://localhost dev)
		Name:     a.stateCookieName(),
		Value:    a.sign(purposeState, payload),
		Path:     "/",
		Expires:  s.Expiry,
		MaxAge:   int(stateTTL / time.Second),
		HttpOnly: true,
		Secure:   a.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) clearStateCookie(w http.ResponseWriter) {
	markSessionResponse(w)
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly+SameSite always set; Secure follows the redirect-URL scheme (off only for http://localhost dev)
		Name:     a.stateCookieName(),
		Value:    "",
		Path:     "/",
		Expires:  expiredCookieTime,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) stateFromRequest(r *http.Request) (statePayload, error) {
	c, err := r.Cookie(a.stateCookieName())
	if err != nil {
		return statePayload{}, a.rejectCookie(purposeState, errNoCookie)
	}
	payload, err := a.verify(purposeState, c.Value)
	if err != nil {
		return statePayload{}, a.rejectCookie(purposeState, err)
	}
	var s statePayload
	if err := json.Unmarshal(payload, &s); err != nil {
		return statePayload{}, a.rejectCookie(purposeState, errCorruptPayload)
	}
	if !a.now().Before(s.Expiry) {
		return statePayload{}, a.rejectCookie(purposeState, errExpired)
	}
	return s, nil
}

// randomToken returns a 256-bit URL-safe random string for state and
// nonce values.
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms; if it does,
		// the process must not continue issuing auth requests.
		panic(fmt.Sprintf("oidcauth: crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

const noStoreCacheControl = "private, no-store"

// markSessionResponse marks a response carrying a credential cookie:
// no cache may store it, private ones included. Every path that writes
// such a cookie calls it, so covering a new one is not a rule the
// author has to remember. Set overwrites the weaker "private".
func markSessionResponse(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", noStoreCacheControl)
}

// markPrivateResponse marks a response as unshareable because its body
// may depend on who is logged in. It merges "private" into whatever
// Cache-Control an outer middleware already set rather than replacing
// it, so an existing "no-store" (or any other directive) survives.
func markPrivateResponse(w http.ResponseWriter) {
	existing := w.Header().Get("Cache-Control")
	if existing == "" {
		w.Header().Set("Cache-Control", "private")
		return
	}
	if hasCacheDirective(existing, "private") {
		return
	}
	w.Header().Set("Cache-Control", existing+", private")
}

// hasCacheDirective reports whether a Cache-Control value already
// carries the named directive. Directive names are case-insensitive
// and comma-separated; a directive may carry an "=" argument.
func hasCacheDirective(value, name string) bool {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if i := strings.IndexByte(part, '='); i >= 0 {
			part = part[:i]
		}
		if strings.EqualFold(part, name) {
			return true
		}
	}
	return false
}

// varyOnCookie tells caches that this response may differ per cookie.
// It is unconditional: gating it on "a session was present" makes the
// condition attacker-controlled, and without it a shared cache that
// stored the anonymous rendering of a URL would serve it to a
// logged-in user. Add, not Set, so a handler's own Vary entries
// survive.
func varyOnCookie(w http.ResponseWriter) {
	w.Header().Add("Vary", "Cookie")
}
