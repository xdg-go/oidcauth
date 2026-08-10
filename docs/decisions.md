# Decision log (append-only)

Format: date — decision — rationale. Newest last. Do not rewrite
history; supersede with a new entry.

## 2026-08-10 — Pass iss to the ForceApprovalIfNewUser callback

`ForceApprovalIfNewUser` changed from `func(sub string) bool` to
`func(iss, sub string) bool` (released as v0.2.0, a breaking change).
The original sub-only signature was chosen for minimalism: an `Auth`
instance is bound to a single issuer, so `iss` is constant per
instance and looked redundant. In practice that minimalism pushed
complexity into callers. The go-vue-app-template skeleton keys
accounts on the compound `(iss, sub)` pair — the only account key this
library's own README permits — so its store had to grow a sub-only
lookup (`HasUserSub`) with cross-issuer semantics no other caller
wanted, plus a standalone `sub` Mongo index solely because the
compound index cannot cover a sub-only query. Closing over the issuer
was possible but broke the clean method-value handoff
(`g.store.HasUser`) by forcing issuer config into the store or a
wrapper closure into auth wiring.

Passing the verified `iss` lets the callback mirror the storage key
directly: callers hand in a store method keyed on `(iss, sub)`, need
no extra index, and cannot false-positive across issuers on colliding
`sub` strings. The cost is one parameter that is constant per `Auth` —
accepted, same as `http.Request` carrying `Host` on a single-vhost
server. Revisit only if the option grows more callback shapes;
sub-only convenience wrappers are not worth the second signature.

## 2026-08-10 — Add network-free SessionClearer instead of exposing cookie attributes

Clearing the session cookie needs only the cookie name and attributes,
all derivable from `Config` plus options — yet the only clear API,
`Auth.ClearSession`, required a constructed `Auth`, and `New` performs
OIDC discovery. Apps that defer construction (the go-vue-app-template
skeleton defers it so boot doesn't couple to broker availability) were
forced into an error branch inside logout-adjacent handlers: "can't
clear a cookie because discovery failed." Released in v0.3.0,
`SessionClearer(cfg, opts...) (func(http.ResponseWriter), error)`
runs the network-free half of construction (validation, defaults,
options — factored into `newAuth`, which `New` now shares) and returns
a clear function that cannot fail; account deletion can always end the
session, broker up or down.

Chosen over two alternatives. Exposing the cookie name/attributes as
getters would leak internals and still make every caller reimplement
the clearing `Set-Cookie` correctly (Path, HttpOnly, SameSite,
Secure). A per-call `ClearSessionCookie(w, cfg, opts...) error` keeps
one function but moves validation to request time, so the error
branch survives in every handler — the constructor shape validates
once at wiring time and defines the runtime error out of existence.
Revisit if more Auth capabilities turn out to be network-free and
callers want them pre-discovery; the `newAuth` split is the seam a
lazier `New` would grow from. **Partly superseded** — the revisit
happened; see "Complete the static split with SessionReader; no
static setter".

## 2026-08-10 — Complete the static split with SessionReader; no static setter (supersedes the revisit clause above)

`SessionReader(cfg, opts...) (func(*http.Request) (User, bool), error)`
joins `SessionClearer` in v0.4.0, built on the same `newAuth` seam.
The principle that decides which operations get a static form is key
ownership: the session cookie is signed with the app's symmetric
`CookieSecret`, so every operation anchored in that secret — clearing
and now reading/verifying — is local and infallible once config is
validated. Without this, an app that defers `New` (to decouple boot
from broker availability) could not verify *existing* sessions during
a broker outage after a restart: valid HMAC-signed cookies produced
401s because `Auth.User` was reachable only through discovery. That
gutted the deferred design's main benefit — the degraded mode it
promised ("existing sessions keep working, only new logins fail") is
exactly what failed.

A static session *setter* is deliberately excluded, and should stay
excluded: minting a session asserts "the issuer verified this user,"
a claim anchored in the issuer's asymmetric keys (discovery, code
exchange, JWKS signature check). A `SessionSetter(cfg)` would let app
code mint sessions for arbitrary claims, severing that attestation —
there, forcing the discovery-backed `Auth` is the security property.
The stable boundary: operations anchored in the app's secret are
static (read, clear); the operation anchored in the issuer's keys
(mint) requires `New`.
