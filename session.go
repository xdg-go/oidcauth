package oidcauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

var errBadCookie = errors.New("oidcauth: invalid or expired cookie")

// sessionPayload is the signed content of the app session cookie.
type sessionPayload struct {
	User   User      `json:"user"`
	Expiry time.Time `json:"exp"`
}

// statePayload is the signed content of the transient login-state
// cookie that binds one auth request to the browser that started it.
type statePayload struct {
	State    string    `json:"state"`
	Nonce    string    `json:"nonce"`
	Verifier string    `json:"verifier"` // PKCE code verifier
	Next     string    `json:"next"`     // post-login redirect (relative)
	Forced   bool      `json:"forced"`   // consent already forced once
	Expiry   time.Time `json:"exp"`
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
		return nil, errBadCookie
	}
	b64, sig := value[:i], value[i+1:]
	gotMAC, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, errBadCookie
	}
	mac := hmac.New(sha256.New, a.cookieSecret)
	mac.Write([]byte(purpose + "." + b64))
	if subtle.ConstantTimeCompare(gotMAC, mac.Sum(nil)) != 1 {
		return nil, errBadCookie
	}
	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, errBadCookie
	}
	return payload, nil
}

func (a *Auth) stateCookieName() string { return a.sessionCookieName + "_state" }

func (a *Auth) setSessionCookie(w http.ResponseWriter, u User) {
	exp := a.now().Add(a.sessionTTL)
	payload, _ := json.Marshal(sessionPayload{User: u, Expiry: exp})
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
		return User{}, errBadCookie
	}
	payload, err := a.verify(purposeSession, c.Value)
	if err != nil {
		return User{}, err
	}
	var s sessionPayload
	if err := json.Unmarshal(payload, &s); err != nil {
		return User{}, errBadCookie
	}
	if !a.now().Before(s.Expiry) {
		return User{}, errBadCookie
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
		return statePayload{}, errBadCookie
	}
	payload, err := a.verify(purposeState, c.Value)
	if err != nil {
		return statePayload{}, err
	}
	var s statePayload
	if err := json.Unmarshal(payload, &s); err != nil {
		return statePayload{}, errBadCookie
	}
	if !a.now().Before(s.Expiry) {
		return statePayload{}, errBadCookie
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
