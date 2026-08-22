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

// errBadCookie reports that a signed cookie was absent, malformed,
// tampered with, or expired. The library's rejection reasons are
// distinct error values that all wrap errBadCookie, so a caller would
// match with errors.Is(err, errBadCookie) and never on the specific
// reason. It stays unexported until an exported API returns it.
var errBadCookie = errors.New("oidcauth: invalid or expired cookie")

// Rejection reasons. Each wraps errBadCookie so that external
// behavior is one error, while logs can name what actually failed.
var (
	errNoCookie         = fmt.Errorf("%w: no cookie present", errBadCookie)
	errBadSignature     = fmt.Errorf("%w: bad signature", errBadCookie)
	errMalformedPayload = fmt.Errorf("%w: malformed payload", errBadCookie)
	errExpired          = fmt.Errorf("%w: expired", errBadCookie)
	errNoIssuedAt       = fmt.Errorf("%w: no issue time", errBadCookie)

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
	mac := hmac.New(sha256.New, a.cookieSecret)
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
	mac := hmac.New(sha256.New, a.cookieSecret)
	mac.Write([]byte(purpose + "." + b64))
	if subtle.ConstantTimeCompare(gotMAC, mac.Sum(nil)) != 1 {
		return nil, errBadSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, errCorruptPayload
	}
	return payload, nil
}

func (a *Auth) stateCookieName() string { return a.sessionCookieName + "_state" }

func (a *Auth) setSessionCookie(w http.ResponseWriter, u User) {
	now := a.now()
	exp := now.Add(a.sessionTTL)
	payload, _ := json.Marshal(sessionPayload{User: u, Expiry: exp, IssuedAt: now.Unix()})
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly+SameSite always set; Secure follows the redirect-URL scheme (off only for http://localhost dev)
		Name:     a.sessionCookieName,
		Value:    a.sign(purposeSession, payload),
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   a.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly+SameSite always set; Secure follows the redirect-URL scheme (off only for http://localhost dev)
		Name:     a.sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// sessionUser returns the verified user from the request's session
// cookie, or an error if the cookie is absent, tampered, or expired.
func (a *Auth) sessionUser(r *http.Request) (User, error) {
	c, err := r.Cookie(a.sessionCookieName)
	if err != nil {
		// Not logged: an absent session cookie is every anonymous
		// request, and logging it would bury the reasons that carry
		// diagnostic value.
		return User{}, errNoCookie
	}
	payload, err := a.verify(purposeSession, c.Value)
	if err != nil {
		return User{}, a.rejectCookie(purposeSession, err)
	}
	var s sessionPayload
	if err := json.Unmarshal(payload, &s); err != nil {
		return User{}, a.rejectCookie(purposeSession, errCorruptPayload)
	}
	// Fail closed: a payload minted before IssuedAt existed (or with
	// the field stripped) decodes to 0 and gets no partial trust. A
	// negative value is equally rejected: it is unreachable while the
	// field is HMAC-covered and only ever set from now.Unix(), but an
	// absolute-lifetime check computed from it would otherwise never
	// expire.
	if s.IssuedAt <= 0 {
		return User{}, a.rejectCookie(purposeSession, errNoIssuedAt)
	}
	if !a.now().Before(s.Expiry) {
		return User{}, a.rejectCookie(purposeSession, errExpired)
	}
	return s.User, nil
}

func (a *Auth) setStateCookie(w http.ResponseWriter, s statePayload) {
	s.Expiry = a.now().Add(stateTTL)
	payload, _ := json.Marshal(s)
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly+SameSite always set; Secure follows the redirect-URL scheme (off only for http://localhost dev)
		Name:     a.stateCookieName(),
		Value:    a.sign(purposeState, payload),
		Path:     "/",
		MaxAge:   int(stateTTL / time.Second),
		HttpOnly: true,
		Secure:   a.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly+SameSite always set; Secure follows the redirect-URL scheme (off only for http://localhost dev)
		Name:     a.stateCookieName(),
		Value:    "",
		Path:     "/",
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
