# oidcauth

[![Go Reference](https://pkg.go.dev/badge/github.com/xdg-go/oidcauth.svg)](https://pkg.go.dev/github.com/xdg-go/oidcauth)

OIDC login for Go web apps using only `net/http`. A thin wrapper over
[go-oidc](https://github.com/coreos/go-oidc) and `golang.org/x/oauth2`
that handles the authorization-code flow with PKCE (S256), state and
nonce validation, and a signed session cookie. It works with any
conformant OIDC issuer; nothing here is provider-specific.

```
go get github.com/xdg-go/oidcauth
```

## Usage

```go
func main() {
	auth, err := oidcauth.NewFromEnv(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	auth.Mount(mux) // /auth/login, /auth/callback, /auth/logout

	mux.Handle("/private", auth.RequireAuth(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, _ := oidcauth.UserFromContext(r.Context())
			fmt.Fprintf(w, "hello %s (%s)", user.Name, user.Sub)
		})))

	log.Fatal(http.ListenAndServe(":8083", mux))
}
```

## Environment variables

| Variable | Meaning |
|---|---|
| `AUTH_ISSUER` | OIDC issuer URL, e.g. `https://auth.example.com` |
| `AUTH_CLIENT_ID` | OAuth2 client id (also the expected ID-token `aud`) |
| `AUTH_CLIENT_SECRET` | OAuth2 client secret |
| `AUTH_REDIRECT_URL` | Absolute callback URL; its path is where the callback handler mounts. Convention: `https://<domain>/auth/callback` |
| `AUTH_COOKIE_SECRET` | HMAC key for cookies, ≥32 bytes (`openssl rand -hex 32`) |

An `http://` redirect URL (local dev) disables the cookie `Secure`
flag; `https://` enables it. Cookies are always `HttpOnly` and
`SameSite=Lax`.

## What it provides

- `LoginHandler` — starts the flow: PKCE S256, random `state` bound to
  a signed short-lived cookie, `nonce` carried into the ID token.
  Accepts `?next=/relative/path` for post-login redirect (open
  redirects are rejected).
- `CallbackHandler` — verifies state, exchanges the code (with the
  PKCE verifier), verifies the ID token (issuer, audience, expiry,
  signature via provider JWKS — all delegated to go-oidc) and the
  nonce, then sets the session cookie.
- `LogoutHandler` — clears the app session cookie only. The issuer's
  session and any upstream (e.g. Google) consent are untouched.
  POST-only, to prevent CSRF-forced logout; drive it from a form or a
  `fetch` POST, not a link.
- `RequireAuth` middleware + `UserFromContext` — gate handlers and
  read the verified `sub`, `email`, `email_verified`, `name`.
- `Auth.User(r)` — optional-auth check for public pages (login vs
  logout links).
- Session: HMAC-signed cookie holding the verified claims;
  `WithSessionTTL` configures lifetime (default 24h).
- `ForceApprovalIfNewUser(func(sub string) bool)` — when the callback
  sees a `sub` your app has not recorded, the auth request restarts
  once with a forced consent prompt, so each user gets an explicit
  consent screen exactly once per app. The restart sends both the
  standard OIDC `prompt=consent` and the pre-OIDC
  `approval_prompt=force`; conformant issuers ignore whichever they
  don't recognize (RFC 6749 §3.1), so this works issuer-neutrally
  without configuration. For an issuer that rejects the combination
  (e.g. Google used directly), `WithForceConsentParams` overrides the
  parameters.

## Key accounts on `sub`, never on email

The ID token's `sub` claim is the **only** value an app may use as an
account key. Store email *alongside* `sub` for display and migration,
but never key on it:

- OIDC guarantees `sub` is unique per issuer and never reassigned. It
  guarantees nothing about email.
- Emails are mutable. A user who changes their address would be
  severed from an email-keyed account.
- Emails are reassignable. Google Workspace recycles addresses;
  keying on email hands the old account to the address's new holder —
  an account takeover.
- A second connector (passkeys, GitHub, ...) can present the same
  email under a different `sub`; email-keying silently merges
  distinct identities.

**Issuer-migration caveat:** `sub` is unique and stable only *within*
an issuer, and its value is opaque — issuers commonly derive it from
internal or upstream identifiers (which authentication backend the
user came through, and that backend's user id). Replacing the issuer
implementation, or changing how it authenticates users upstream, can
therefore change every `sub` even when the issuer URL stays the same.
A migration must either preserve `sub` values or map old→new via a
stored secondary attribute such as email. This is why you store email
alongside `sub` even though you never key on it.

## License

Apache 2.0. See [LICENSE](LICENSE).
