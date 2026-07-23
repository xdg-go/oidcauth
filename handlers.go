package oidcauth

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// LoginHandler starts the authorization-code flow: it generates state,
// nonce, and a PKCE (S256) verifier, binds them to the browser via a
// signed short-lived cookie, and redirects to the issuer.
//
// Query parameters:
//   - next: relative path to return to after login (default "/").
//   - force: "1" requests a forced consent prompt (used internally by
//     the [ForceApprovalIfNewUser] restart).
func (a *Auth) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		st := statePayload{
			State:    randomToken(),
			Nonce:    randomToken(),
			Verifier: oauth2.GenerateVerifier(),
			Next:     sanitizeNext(r.URL.Query().Get("next")),
			Forced:   r.URL.Query().Get("force") == "1",
		}
		a.setStateCookie(w, st)

		opts := []oauth2.AuthCodeOption{
			oidc.Nonce(st.Nonce),
			oauth2.S256ChallengeOption(st.Verifier),
		}
		if st.Forced {
			for k, v := range a.forceConsentParams {
				opts = append(opts, oauth2.SetAuthURLParam(k, v))
			}
		}
		http.Redirect(w, r, a.oauth.AuthCodeURL(st.State, opts...), http.StatusFound)
	})
}

// CallbackHandler completes the flow: it checks state against the
// signed cookie, exchanges the code (with the PKCE verifier), verifies
// the ID token (issuer, audience, expiry, signature) and its nonce,
// then sets the app session cookie and redirects to the `next` path
// captured at login.
func (a *Auth) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		st, err := a.stateFromRequest(r)
		// One-shot: whatever happens next, this login attempt is spent.
		a.clearStateCookie(w)
		if err != nil {
			http.Error(w, "login session missing or expired; retry login", http.StatusBadRequest)
			return
		}

		q := r.URL.Query()
		if errCode := q.Get("error"); errCode != "" {
			status := http.StatusBadGateway
			if errCode == "access_denied" {
				status = http.StatusForbidden
			}
			http.Error(w, "authentication failed: "+errCode, status)
			return
		}
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "missing authorization code", http.StatusBadRequest)
			return
		}

		token, err := a.oauth.Exchange(r.Context(), code, oauth2.VerifierOption(st.Verifier))
		if err != nil {
			http.Error(w, "code exchange failed", http.StatusBadGateway)
			return
		}
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "issuer returned no id_token", http.StatusBadGateway)
			return
		}
		idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			http.Error(w, "id token verification failed", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(st.Nonce)) != 1 {
			http.Error(w, "nonce mismatch", http.StatusUnauthorized)
			return
		}

		var claims struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "unreadable id token claims", http.StatusBadGateway)
			return
		}
		user := User{
			Issuer:        idToken.Issuer,
			Sub:           idToken.Subject,
			Email:         claims.Email,
			EmailVerified: claims.EmailVerified,
			Name:          claims.Name,
		}
		if len(a.extraClaims) > 0 {
			var all map[string]json.RawMessage
			if err := idToken.Claims(&all); err != nil {
				http.Error(w, "unreadable id token claims", http.StatusBadGateway)
				return
			}
			for _, name := range a.extraClaims {
				if raw, ok := all[name]; ok {
					if user.Extra == nil {
						user.Extra = make(map[string]json.RawMessage, len(a.extraClaims))
					}
					user.Extra[name] = raw
				}
			}
		}

		// First visit from an unfamiliar sub: restart the auth request
		// once with a forced consent prompt. st.Forced guards against
		// looping when the app has not yet recorded the sub.
		if a.knownSub != nil && !st.Forced && !a.knownSub(user.Sub) {
			v := url.Values{"force": {"1"}}
			if st.Next != "/" {
				v.Set("next", st.Next)
			}
			http.Redirect(w, r, a.loginPath+"?"+v.Encode(), http.StatusFound)
			return
		}

		a.setSessionCookie(w, user)
		http.Redirect(w, r, st.Next, http.StatusFound)
	})
}

// LogoutHandler clears the app session cookie and redirects. It only
// ends the app's session: the issuer's own session and any upstream
// (e.g. Google) consent are unaffected.
//
// Logout is POST-only, for two reasons. CSRF: with SameSite=Lax,
// cross-site subresources (<img>, script) never carry the session
// cookie, but top-level GET navigation does — so a GET logout is
// forceable by any cross-site link, while Lax withholds cookies from
// cross-site POSTs, making POST + Lax a complete defense with no CSRF
// token. Accidents: link prefetchers, browser prerendering, and email
// scanners issue GETs and would randomly end sessions; nothing
// prefetches a form. Log out from a form (or fetch) that issues a
// POST.
func (a *Auth) LogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.clearSessionCookie(w)
		http.Redirect(w, r, a.postLogoutRedirect, http.StatusFound)
	})
}

// ClearSession removes the app session cookie without redirecting.
// Use it inside app handlers that end the session as part of their own
// flow — e.g. account deletion — where redirecting the in-flight POST
// to the POST-only logout endpoint is not possible. It only ends the
// app's session, exactly like LogoutHandler.
func (a *Auth) ClearSession(w http.ResponseWriter) {
	a.clearSessionCookie(w)
}

// sanitizeNext restricts post-login redirects to same-origin relative
// paths, defeating open-redirect abuse. Anything else becomes "/".
func sanitizeNext(next string) string {
	if next == "" ||
		!strings.HasPrefix(next, "/") ||
		strings.HasPrefix(next, "//") ||
		strings.ContainsAny(next, "\\\r\n") {
		return "/"
	}
	return next
}
