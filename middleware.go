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
// Authenticate is the mount point for sliding session renewal: a valid
// session inside its renew window gets a renewed Set-Cookie, written
// before next runs so it cannot lose a race with the handler's own
// headers. Cache headers are written at entry as well. The lifetime
// and caching rules -- the two clocks, the max-lifetime cap, which
// Cache-Control each response gets, and the handler that overwrites it
// -- are in the package doc under "Session lifetime" and "Caching".
func (a *Auth) Authenticate(next http.Handler) http.Handler {
	return a.authenticate(next, true)
}

// AuthenticateNoRenew is [Auth.Authenticate] without session renewal:
// it verifies and populates the context but never writes a session
// cookie, so the strongest cache header it writes is
// Cache-Control: private. Use it on routes that must not emit a
// credential.
//
// It suppresses renewal only for the routes it alone serves: an
// [Auth.Authenticate] nested inside it still renews (the strongest
// mount wins; see "Middleware" in the package doc). Keep at least one
// [Auth.Authenticate] in the user's normal browsing path, or sessions
// expire a full lifetime after login no matter how active the user
// is.
func (a *Auth) AuthenticateNoRenew(next http.Handler) http.Handler {
	return a.authenticate(next, false)
}

func (a *Auth) authenticate(next http.Handler, renew bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, r := a.resolve(w, r)
		// The renewal decision belongs to the strongest mount, not the
		// outermost: a renewing mount nested inside a non-renewing one
		// (or inside RequireAuth's inline verify) still renews, as
		// long as no mount has made that decision yet. So: one
		// verification, at most one session Set-Cookie.
		if renew && res.ok && !res.renewed {
			// Renewal happens before the handler runs, so the
			// Set-Cookie cannot lose a race with headers the handler
			// writes.
			a.renewSessionCookie(w, res.session, res.at)
			res.renewed = true
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, res))
		}
		next.ServeHTTP(w, r)
	})
}

// resolve returns this request's session, verifying the cookie only if
// no mount of this Auth already did, so nesting the middlewares
// verifies exactly once. It returns the request to pass down: a fresh
// verify carries the sentinel on the context, a reused one is
// unchanged.
//
// A fresh verify is also the only place the response's cache headers
// are written, which is what keeps their ordering from mattering. They
// go on before the handler or any renewal runs, and every later write
// this package makes -- a renewed cookie, a login, a logout -- only
// upgrades "private" to "private, no-store". A reused result means an
// earlier mount already wrote them.
func (a *Auth) resolve(w http.ResponseWriter, r *http.Request) (authResult, *http.Request) {
	// Only this Auth's own sentinel is trusted (see [authResult]).
	if res, ok := r.Context().Value(ctxKey{}).(authResult); ok && res.owner == a {
		return res, r
	}
	varyOnCookie(w)
	// One clock reading covers verification and any renewal decision
	// made from it, so a request cannot straddle the moment a session
	// expires.
	now := a.now()
	s, err := a.sessionFromRequestAt(r, now)
	res := authResult{owner: a, session: s, ok: err == nil, at: now}
	if res.ok {
		// The response may depend on who is logged in, so a shared
		// cache must not serve it to another user. Anonymous requests
		// keep whatever the app chose, so public pages stay
		// shared-cacheable.
		markPrivateResponse(w)
	}
	return res, r.WithContext(context.WithValue(r.Context(), ctxKey{}, res))
}

// RequireAuth wraps next so it only runs with a valid app session.
// The verified [User] is placed in the request context for
// [UserFromContext]. Unauthenticated GET/HEAD requests are redirected
// to the login handler with `next` set to the requested path; other
// methods get 401.
//
// RequireAuth composes on [Auth.Authenticate]: it reuses an outer
// mount's result, or verifies inline, writing the same cache headers a
// non-renewing mount would. Either way the cookie is verified exactly
// once. RequireAuth itself never renews, though an [Auth.Authenticate]
// mounted inside it still does; a tree with no Authenticate at all
// never renews, so sessions expire a full lifetime after login no
// matter how active the user is. See "Middleware" in the package doc
// for mounting guidance.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, r := a.resolve(w, r)
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
