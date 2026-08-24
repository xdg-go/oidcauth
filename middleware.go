package oidcauth

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// ctxKey is the package-scoped key under which the authResult
// sentinel is stored. Being package-scoped rather than per-Auth means
// this package assumes a single *Auth per process: that assumption is
// what lets [UserFromContext] stay a plain function instead of a
// method. Two *Auth values serving the same process (different cookie
// secrets or cookie names) is not a supported deployment.
type ctxKey struct{}

// authResult is the context sentinel the Authenticate middlewares
// store on every request, anonymous or not. Its presence means "a
// verifying middleware already ran"; ok reports whether it found a
// valid session. Storing it unconditionally is what lets
// [Auth.RequireAuth] tell "middleware never ran" from "not logged in".
type authResult struct {
	// owner is the *Auth that verified this request. A sentinel from a
	// different *Auth is ignored rather than trusted, so a session valid
	// under one cookie secret cannot authenticate a request through
	// another (see [ctxKey] for why the key is package-scoped).
	owner *Auth
	// session is the verified payload, kept whole because a renewing
	// mount nested inside a non-renewing one still needs the expiry
	// and issue time to decide about renewal. It is meaningful only
	// when ok is true.
	session sessionPayload
	ok      bool
	// at is the clock reading that verified this request. A later
	// renewal decision reuses it so one request cannot straddle the
	// moment a session expires.
	at time.Time
	// renewed records that some mount has already made the renewal
	// decision for this request, whether or not it ended up writing a
	// cookie. It keeps the session Set-Cookie count at most one.
	renewed bool
}

// Authenticate wraps next with session verification: it verifies the
// session cookie, stores the result in the request context for
// [UserFromContext], and never rejects, so anonymous requests pass
// through untouched. Mount it as the outermost wrapper around your
// whole handler tree; [Auth.RequireAuth] composes on it.
//
// Authenticate is the mount point for sliding session renewal: when a
// valid session has entered the renew window before its expiry it
// writes a renewed Set-Cookie before calling next, so the cookie cannot
// lose a race with the handler's own headers. The renewed cookie keeps
// the original issue time and its expiry is clamped to the max
// lifetime, so renewal slides a session forward but never past that
// deadline. A session that has reached the max lifetime is rejected
// outright, even while its own cookie expiry is still in the future,
// exactly as an expired one is.
//
// Cache headers are written at entry too. Every response gets
// Vary: Cookie. A response carrying a renewed session cookie gets
// Cache-Control: private, no-store, because it carries a credential;
// a verified session with no renewal gets Cache-Control: private.
// Anonymous requests are left alone, so public pages stay
// shared-cacheable. Because these are written before next runs, a
// handler that sets its own Cache-Control on such a response wins and
// defeats them; the library does not prevent that.
func (a *Auth) Authenticate(next http.Handler) http.Handler {
	return a.authenticate(next, true)
}

// AuthenticateNoRenew is [Auth.Authenticate] without session renewal:
// it verifies and populates the context but will never write a session
// cookie. Use it on routes that must not emit a credential.
//
// It writes the same cache headers as [Auth.Authenticate], except
// that with no renewal the strongest it writes is
// Cache-Control: private.
//
// It suppresses renewal only for the routes it alone serves: an
// [Auth.Authenticate] nested inside it still renews (see the package
// doc on middleware for why).
//
// At least one Authenticate mount must sit in the user's normal
// browsing path, or sessions expire a full lifetime after login no
// matter how active the user is.
func (a *Auth) AuthenticateNoRenew(next http.Handler) http.Handler {
	return a.authenticate(next, false)
}

func (a *Auth) authenticate(next http.Handler, renew bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		varyOnCookie(w)
		// Reuse this Auth's own sentinel when an outer mount already
		// verified the request, so nesting the middlewares verifies
		// the cookie exactly once. The renewal decision belongs to
		// the strongest mount, not the outermost: a renewing mount
		// nested inside a non-renewing one (or inside RequireAuth's
		// inline verify) still renews, as long as no mount has made
		// that decision yet. So: one verification, at most one
		// session Set-Cookie.
		if res, verified := r.Context().Value(ctxKey{}).(authResult); verified && res.owner == a {
			// Skip when a renewal was already recorded: that
			// response carries a session cookie and is marked
			// "private, no-store", which Set would downgrade.
			if res.ok && !res.renewed {
				markPrivateResponse(w)
				if renew {
					a.renewSessionCookie(w, res.session, res.at)
					res.renewed = true
					r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, res))
				}
			}
			next.ServeHTTP(w, r)
			return
		}
		// One clock reading covers verification and the renewal
		// decision, so a request cannot straddle the moment a session
		// expires.
		now := a.now()
		s, err := a.sessionFromRequestAt(r, now)
		// A verified session means the response may depend on who is
		// logged in, so it must not be shared-cached. Anonymous
		// requests keep whatever Cache-Control the app chose. A
		// renewal below upgrades this to "private, no-store".
		if err == nil {
			markPrivateResponse(w)
		}
		// Renewal happens before the handler runs, so the Set-Cookie
		// cannot lose a race with headers the handler writes.
		if err == nil && renew {
			a.renewSessionCookie(w, s, now)
		}
		res := authResult{owner: a, session: s, ok: err == nil, at: now, renewed: renew}
		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), ctxKey{}, res)))
	})
}

// verifySession is the inline verify used by [Auth.RequireAuth] when
// no Authenticate mount ran. It never renews, so the sentinel it
// returns leaves the renewal decision open for a renewing mount
// nested below it.
func (a *Auth) verifySession(r *http.Request) authResult {
	now := a.now()
	s, err := a.sessionFromRequestAt(r, now)
	return authResult{owner: a, session: s, ok: err == nil, at: now}
}

// RequireAuth wraps next so it only runs with a valid app session.
// The verified [User] is placed in the request context for
// [UserFromContext]. Unauthenticated GET/HEAD requests are redirected
// to the login handler with `next` set to the requested path; other
// methods get 401.
//
// RequireAuth composes on [Auth.Authenticate]: when an outer
// Authenticate from the same Auth has already verified the request it
// enforces from the context, and otherwise it verifies inline. Either
// way the session cookie is verified exactly once. RequireAuth itself
// never renews, but an [Auth.Authenticate] mounted inside it still
// does.
//
// When it does verify inline it writes the same cache headers an
// [Auth.Authenticate] mount would for a non-renewing request:
// Vary: Cookie always, and Cache-Control: private once a session
// verifies. When an outer Authenticate already ran, that mount has
// written them and RequireAuth adds nothing.
//
// A tree with no Authenticate at all verifies but never renews, so
// sessions expire a full lifetime after login no matter how active
// the user is. Mount at least one Authenticate in the user's normal
// browsing path.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only this Auth's own sentinel is trusted (see [authResult]).
		res, verified := r.Context().Value(ctxKey{}).(authResult)
		if !verified || res.owner != a {
			// No Authenticate mount ran, so nothing has written the
			// cache headers for this response yet and this inline
			// verify is the whole of the request's session handling.
			varyOnCookie(w)
			res = a.verifySession(r)
			if res.ok {
				markPrivateResponse(w)
			}
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, res))
		}
		if !res.ok {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				v := url.Values{"next": {r.URL.RequestURI()}}
				http.Redirect(w, r, a.loginPath+"?"+v.Encode(), http.StatusFound)
				return
			}
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// UserFromContext returns the [User] stored by [Auth.Authenticate],
// [Auth.AuthenticateNoRenew], or [Auth.RequireAuth]. ok is false both
// when no such middleware ran and when it found no valid session; use
// it on public pages that adapt to login state (login vs logout links)
// as well as behind RequireAuth.
//
// This is a plain function, not a method, because the package assumes
// a single *Auth per process (see [ctxKey]); it reports whatever
// sentinel is on the context without checking which *Auth wrote it.
func UserFromContext(ctx context.Context) (u User, ok bool) {
	res, ok := ctx.Value(ctxKey{}).(authResult)
	if !ok || !res.ok {
		return User{}, false
	}
	return res.session.User, true
}
