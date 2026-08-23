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
session, broker up or down. **Superseded** — see "Move laziness into
the library: I/O-free New, optional Connect".

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
(mint) requires `New`. **Superseded** — see "Move laziness into the
library: I/O-free New, optional Connect". The no-static-setter
principle survives: minting still requires successful discovery.

## 2026-08-10 — Move laziness into the library: I/O-free New, optional Connect (supersedes SessionClearer/SessionReader above)

The static split (v0.3.0/v0.4.0) pushed lazy-construction complexity
into every app: each one that wanted "boot even if the broker is
down" had to defer `New`, wire the statics, and manage the retry
itself. That is the complexity this library exists to absorb, so
v0.5.0 moves the laziness inside, MongoDB-driver style: `New(cfg,
opts...)` validates and performs no I/O; OIDC discovery runs on
demand from the login and callback handlers, or eagerly via
`Connect(ctx)` for apps that want startup to fail on a bad issuer.
`SessionReader` and `SessionClearer` are deleted — `Auth.User` and
`Auth.ClearSession` are HMAC-anchored and already work on an
undiscovered `Auth`, so the degraded mode ("existing sessions keep
working, only new logins 503") now falls out of ordinary use with no
extra API. `New` also drops its `context.Context`: go-oidc v3.20's
`NewProvider` uses the ctx only for the discovery call and to extract
an `http.Client` (its `RemoteKeySet` is built on
`context.Background()`; JWKS-fetch cancellation rides the ctx passed
to `Verify`), so there is no retained lifecycle for a constructor ctx
to govern — see coreos/go-oidc v3.20.0 oidc/oidc.go:250. This leans
on go-oidc internals, noted in a comment at the `oidc.NewProvider`
call site in `Auth.discover`.

Discovery runs one attempt at a time via
`golang.org/x/sync/singleflight` (v0.22.0) `Group.DoChan`, chosen
over a hand-rolled mutex/channel dance: concurrency deduplication is
exactly the "battle-tested algorithm" case for taking a dependency —
a subtle race missed in bespoke code costs far more than `x/sync`,
which shares provenance and maintenance with the already-required
`x/oauth2`. The flight runs detached, so a caller's canceled ctx
bounds only that caller's wait (DoChan's buffered channel means an
abandoned wait leaks nothing), while the attempt itself is bounded by
the internal client timeout below. The library owns the policy
singleflight doesn't provide — sticky success (`verifier` as the
discovered flag) and a 2s failure cooldown so a down issuer is not
re-probed per request — checked inside the flight, under the lock,
where they cannot race with a flight completing. All three network
paths — discovery, JWKS fetch, token exchange — use one internal
`http.Client` with a 10s timeout (via `oidc.ClientContext` and the
`oauth2.HTTPClient` context key), because the timeout-less
`http.DefaultClient` would let a hung issuer pin requests
indefinitely; the client is deliberately unexported, with
`WithHTTPClient` as a purely additive escape hatch if proxy/TLS needs
ever appear. Handlers answer 503 with `Retry-After: 2` while
discovery has not succeeded; the callback gates before touching the
one-shot state cookie so an outage does not burn the login attempt.
Revisit the cooldown constant only with evidence; revisit the
internal-client decision if a consumer needs a custom transport.

## 2026-08-21 — Move session renewal into middleware and delete Auth.User(r)

Sliding renewal needs an `http.ResponseWriter` to emit `Set-Cookie`, so
it cannot live behind a read-only accessor. The library exposes `func
(a *Auth) Authenticate(next http.Handler) http.Handler`: it verifies the session
cookie, renews it when the session is past the half-life of the session
lifetime, stores the user in the request context, and never rejects, so
anonymous requests pass through untouched. `RequireAuth` composes on
`Authenticate` and rejects only when the context carries no user;
`UserFromContext` stays a pure context read. `Auth.User(r
*http.Request)` is deleted. Because `Authenticate` is the outermost
wrapper it necessarily runs before the handler writes anything, which
makes correct `Set-Cookie` ordering structural instead of a rule a
caller has to remember.

The rejected alternatives all leaked the writer requirement back to
callers. Changing the signature to `User(w, r)` keeps a getter with a
hidden `Set-Cookie` side effect and still leaves two divergent verify
paths. Renewing only inside `RequireAuth` means an app whose routes are
all public never renews, and a visitor who only browses public pages
watches a live session lapse. Adding a second, renewing accessor beside
`User` gives the API two functions that differ only by an invisible side
effect. To keep the composed and bare forms both correct, `Authenticate`
always stores a sentinel value in the context, even for anonymous
requests: `RequireAuth` treats the sentinel's presence as "middleware
already ran, enforce from context" and its absence as "verify inline,
then enforce". Without the sentinel, a route nobody wrapped renders
logged out for a logged-in user, and nothing at runtime reports the
mistake. With it, `Authenticate(mux)` plus `RequireAuth`, and bare
`RequireAuth`, each perform exactly one verification.

## 2026-08-21 — Write session cache headers at middleware entry, no ResponseWriter wrapper

Any response the library writes a session cookie onto (renewal, login
callback, logout) also carries `Cache-Control: private, no-store`, and
`AuthenticateNoRenew` sets `Cache-Control: private` when it finds a
valid session. Both headers, and the renewal `Set-Cookie` itself, are
written at middleware entry, before the next handler is called. There
is no `http.ResponseWriter` wrapper re-asserting the header at
`WriteHeader` time. A wrapper is only necessary when the cookie's
contents depend on what the handler did; oidcauth's renewal decision
depends on nothing but the incoming cookie and the clock, so it is
already known at entry. `alexedwards/scs` needs its
`sessionResponseWriter` precisely because handlers mutate its session
data; oauth2-proxy, whose refresh is decided up front like ours, writes
`Set-Cookie` straight to the real writer from `refreshSessionIfNeeded`.

The header values are load-bearing rather than belt-and-braces: RFC 9111
§7.3 states that `Set-Cookie` does not inhibit caching, and AWS
CloudFront documents that it caches `Set-Cookie` and returns it "to
viewers on all cache hits". nginx, Varnish, and Fastly refuse by
default; Cloudflare under "Cache Everything" with an edge TTL strips
the `Set-Cookie` and caches the body, breaking login rather than
leaking it. A response holding a session cookie is a credential, and a
misconfigured CDN would hand one user's cookie to the next requester, a
total auth bypass. Every response through the middleware also gets
`Vary: Cookie`; see the next entry.

Entry-time writing gives up last-write-wins over a handler that sets
`Cache-Control: public`, and the README says so. That is the price of
avoiding real wrapper risk: `ReadFrom` is not covered by
`http.NewResponseController`, so an `Unwrap`-only wrapper silently
loses the sendfile fast path, while a wrapper that *does* forward
`ReadFrom` must also fire the header logic there or every
`ServeContent` response bypasses it. Code that type-asserts
`w.(http.Flusher)` rather than using `NewResponseController` -- still
common, e.g. gorilla/handlers -- breaks against an `Unwrap`-only
wrapper too. Note also that `scs` settled on `Header().Add` rather than
`Set`, so even the closest Go prior art does not achieve
last-write-wins. Revisit if the library ever needs to write a cookie
whose contents the handler influences.

`AuthenticateNoRenew` is the variant for routes that must never emit a
credential: it verifies and populates the context but never renews. Its
justification is "do not emit credentials on this route", *not*
cacheability -- a page that adapts to login state is exactly the page
that must not be shared-cached, and dropping the `Set-Cookie` removes
the very signal that triggers default CDN bypass. Its doc comment must
warn that at least one renewing mount has to sit in the user's normal
path, or sessions expire at the session lifetime no matter how active
the user is. A variadic middleware option or an `Option` on `Auth` was
rejected because the property is per-mount, not per-instance.

## 2026-08-21 — Send Vary: Cookie unconditionally

Every response through the middleware gets `Vary: Cookie`, added at
entry with no branch. Fastly warns that varying on `Cookie` "will
likely be so specific as to make the response impossible to use again",
and that is accurate -- but for a response whose body depends on login
state, unreusable is the correct answer, and the alternative Fastly
recommends (normalize the cookie into a low-cardinality header at the
edge) is CDN configuration a Go library cannot express. Without it, a
shared cache that stored the anonymous rendering of a URL will serve it
to a logged-in user.

Setting it conditionally, only when a session is present, was rejected:
the condition is the thing an attacker controls, and the Go ecosystem
has converged on the unconditional form -- `alexedwards/scs` (since
commit `91e3021b`, 2021), `gorilla/csrf`, and `justinas/nosurf` all set
it on every request. Django is the one major framework that gates it,
on session *access* rather than write. Use `Header().Add`, not `Set`,
so a handler's own `Vary` entries survive.

## 2026-08-21 — Keep 90d session lifetime / 1y max session lifetime defaults

The defaults ship as a 90 day session lifetime with a 1 year maximum
session lifetime, deliberately against adversarial review that argued
for 30d/90d. The target consumers are internal tools where a re-login
every quarter is friction without a matching threat, and the Phase 4
per-user revocation hook (an app-side revocation timestamp compared
against the session's `IssuedAt`) is the mitigation for the cases that
matter. Shorter defaults were rejected as buying little against an
operator who can already revoke. These numbers shipped before renewal
and maximum-lifetime enforcement landed, chosen over an interim 24h or
7d so the defaults would not move twice; both now enforce, so the
shipped behavior matches the documented one.

The consequence to document in the README: renewal is not
re-authentication. Claims freeze at login, so a user disabled at the
IdP or whose group membership changed can hold a valid session until
the maximum lifetime deadline. Revisit these numbers if oidcauth is
adopted for anything internet-facing, or if the revocation hook does
not land.

## 2026-08-22 — Add a cookie secret key ring; reject per-session IDs

`Config.CookieSecret` becomes the signing key of an ordered ring, with
`Config.PreviousCookieSecrets` holding verify-only predecessors
(`AUTH_COOKIE_SECRET_PREVIOUS`, comma-separated). `verify` tries each
key in turn; `sign` always uses the current one. The motivation is that
a single key made rotation a hard cutover that logs out every user and
breaks logins mid-redirect, so the only global kill switch was too
expensive to ever rehearse. With a ring, rotation is routine: promote,
deploy, and retire the old key one full session lifetime later, by which
point every live session has renewed and been re-signed. Retiring the
old key immediately, rather than after a delay, is the deliberate
logout-everyone variant. The ring size is deliberately uncapped: each
key costs one HMAC against an unauthenticated garbage cookie, so a long
ring is a work multiplier, but that is a documented cost for the
operator to weigh rather than a limit the library imposes.

Adding a random per-session ID to the payload, so an app could denylist
individual sessions, was considered and rejected. A stolen cookie is a
byte-identical clone, so its ID matches the victim's -- per-session
revocation cannot evict the attacker while sparing the legitimate
session, which was the security case for it. What remains is
convenience: revoking one device's login instead of all of them. That
is worth little here, because re-login through an IdP whose own session
is still valid is a single redirect. The labeling problem finishes the
argument: an opaque ID is meaningless to a user without a server-side
record of user agent, address, and last-seen -- exactly the session
table this design rejects, at which point the signed cookie is only a
bearer token pointing at server state. The Phase 4 revocation epoch
covers offboarding and suspected compromise with far less machinery.
Revisit only if oidcauth needs per-device session management as a
product feature, not as a security control.

One consequence to carry into Phase 4's doc comment: "log out
everywhere" must set the epoch to `now`, not to the current cookie's
`IssuedAt`. A strictly-before comparison against your own `IssuedAt`
spares your session and its clone alike, since they share the
timestamp. The user re-authenticates; that is the honest primitive.

## 2026-08-22 — Assume one *Auth per process; keep UserFromContext a function

`Authenticate` now stores an unexported `authResult` sentinel on every
request, anonymous ones included, so a later `RequireAuth` can tell
"middleware never ran" from "not logged in" and verify at most once.
That sentinel lives under a package-scoped context key, which means two
`*Auth` values in one process, with different cookie secrets or cookie
names, would otherwise read each other's results. The supported
deployment is a single `*Auth` per process, and that assumption is what
lets `UserFromContext` stay a plain package-level function taking only a
`context.Context`.

Instance-scoped context keys were the alternative: give each `Auth` its
own key and a foreign sentinel becomes invisible rather than
detected, defining the failure out of existence. It lost on API cost,
since `UserFromContext` would have to become the method
`a.UserFromContext(ctx)` for every consumer, to fix a case no consumer
has. The `authResult.owner == a` check in `RequireAuth` stays as cheap
belt and braces, not as support for the multi-`Auth` case. Revisit if a
real consumer needs to mount two `Auth` values in one process, at which
point the method form is the honest fix.

## 2026-08-22 — Rename the session knobs to WithSessionLifetime and WithSessionMaxLifetime

`WithSessionIdleWindow` becomes `WithSessionLifetime` and
`WithSessionAbsoluteCap` becomes `WithSessionMaxLifetime` (fields
`sessionLifetime` and `maxSessionLifetime`). "Idle window" was
inaccurate. An OWASP idle or inactivity timeout runs from the user's
last request; this library measures from the last renewal, and renewal
fires only on a request past the half-life, so an active user's session
expires between half a lifetime and a full lifetime after their last
request. Under `AuthenticateNoRenew` alone it does not slide at all. A
reader trusting the old name would assume a deadline up to half a
window fresher than reality. The closer prior art is ASP.NET Core
cookie authentication's sliding expiration (`ExpireTimeSpan` plus
`SlidingExpiration`), which also renews only past the half-life.

The new names describe one kind of thing, a lifetime, differing only in
origin: `WithSessionLifetime` runs from each cookie write and slides
when `Authenticate` renews; `WithSessionMaxLifetime` runs from the
original login and never moves. Both are hard deadlines, and a session
dies at whichever comes first. A follow-up will add
`WithSessionRenewWindow` to make the half-life an explicit knob rather
than a constant readers have to infer from the name.

## 2026-08-22 — Add WithSessionRenewWindow instead of a hardcoded half-life

Renewal used to fire at `Expiry - sessionLifetime/2`. The divisor was
an implementation detail of `renewSessionCookie` that callers could
only learn from prose, yet it set the real worst-case staleness of an
idle session. Naming it makes renewal a documented
feature of the session model rather than a constant readers infer, and
it makes a configuration nobody could reach before reachable: with
`renewWindow == sessionLifetime` every request renews, which is the
true last-request idle timeout the old `WithSessionIdleWindow` name
wrongly promised.

The default is a literal, `renewWindow: 45 * 24 * time.Hour`, sitting
in the same struct as the 90-day lifetime and the 365-day max, not a
value computed from `sessionLifetime` after the option loop. A reader
can see all three defaults and check their consistency by reading one
struct, and there is no option-order dependence or unset sentinel to
reason about. A caller who passes a
short `WithSessionLifetime` and no `WithSessionRenewWindow` now fails
construction against the 45-day default instead of getting a silently
scaled window. This library already makes that trade for the
lifetime/max pair, which rejects rather than substituting, so the error
message names both values and says which option to set.

`renewWindow == sessionLifetime` is legal; only `>` is rejected. Equal
is a coherent, useful policy, and refusing it would only push callers
toward `lifetime - 1ns`. Greater is not a policy at all: the trigger
`now >= Expiry - renewWindow` would be true from the instant the cookie
is written, so every value above the lifetime collapses to the same
renew-on-every-request behavior that equality already expresses. The
full rule is renew window <= session lifetime <= max lifetime.
