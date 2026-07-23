package oidcauth

import (
	"context"
	"net/http"
	"net/url"
)

type ctxKey struct{}

// RequireAuth wraps next so it only runs with a valid app session.
// The verified [User] is placed in the request context for
// [UserFromContext]. Unauthenticated GET/HEAD requests are redirected
// to the login handler with `next` set to the requested path; other
// methods get 401.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := a.sessionUser(r)
		if err != nil {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				v := url.Values{"next": {r.URL.RequestURI()}}
				http.Redirect(w, r, a.loginPath+"?"+v.Encode(), http.StatusFound)
				return
			}
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

// UserFromContext returns the [User] stored by [Auth.RequireAuth].
// ok is false outside a RequireAuth-wrapped handler.
func UserFromContext(ctx context.Context) (u User, ok bool) {
	u, ok = ctx.Value(ctxKey{}).(User)
	return u, ok
}

// User returns the request's session user, if any. Use it on public
// pages that adapt to login state without requiring it (e.g. showing
// login vs logout links). Handlers behind [Auth.RequireAuth] should
// prefer [UserFromContext].
func (a *Auth) User(r *http.Request) (u User, ok bool) {
	u, err := a.sessionUser(r)
	return u, err == nil
}
