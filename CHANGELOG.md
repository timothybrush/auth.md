# auth.md Changelog

## v0.5.0 (2026-06-04)

Gates first-time linking of an ID-JAG to an existing account behind a user-confirmation ceremony, and rejects ID-JAGs with missing or stale `auth_time`. Without step-up, any trusted provider could mint an ID-JAG with `email_verified: true` for a victim's email and silently take over their account at the service. Without the `auth_time` gate, an agent could ride an indefinitely-stale upstream session.

### Added

- `interaction_required` (401) from `/agent/identity` for ID-JAG flows when the ID-JAG matches an existing account by verified email/phone but no `(iss, sub)` delegation exists yet. Body carries the same RFC 8628-shaped ceremony block as verified-email registration; the agent surfaces `user_code` + `verification_uri` to the user, who signs in at the service and confirms the link on a provider-aware `/claim` page ("Link `<Provider>` to your account?").
- `login_required` (401) from `/agent/identity` for ID-JAG flows when `auth_time` is missing, too old, or set unreasonably in the future. `WWW-Authenticate` carries `max_age`. The agent's recourse is at its provider (`prompt=login` or equivalent) — nothing the user can do at the service helps.
- `config.idJagMaxAuthAgeSeconds` (default 3600s) — hard-required upper bound on the age of `auth_time` claims. Applied universally, including known `(iss, sub)` delegations, to prevent indefinite session piggy-backing.
- Trust-list entries gain a `displayName` field — service-controlled copy rendered on `/claim` so a malicious provider can't pick its own UI string.

### Changed

- `matcher.ts` returns a discriminated `MatchResult` (`{ kind: "match" | "step_up_required" }`). Email/phone matches no longer silently bind delegations; they return `step_up_required` and let the route gate the binding via the ceremony.
- `findOrCreateIdJagRegistration` unified into one function keyed on `(iss, sub, aud)` with a `context: { user } | { email }` discriminator. Same registration shape for clean-match and step-up — step-up is just the not-yet-claimed state of the same registration. `completeClaim` for `id_jag` registrations now calls `upsertDelegation` on success so the binding survives.
- `verify.ts` rejects ID-JAGs whose `auth_time` is missing, older than `idJagMaxAuthAgeSeconds + clockSkewSeconds`, or further than `clockSkewSeconds` in the future. The future bound closes a session-piggybacking gap where a compromised trusted issuer could mint tokens with a far-future `auth_time` and bypass the freshness check.
- `/claim` page renders provider-aware copy for ID-JAG step-up registrations ("Link `<Provider>` to your account?") using the service's trust-list `displayName`.
- Race resolution at `/agent/identity` (ID-JAG step-up): when a concurrent ceremony binds the delegation while this request is matching, the response is now the same 200 + `identity_assertion` the clean-match path would emit, instead of a 409 the agent had to retry on.

## v0.4.0 (2026-06-04)

Inverts the claim ceremony and consolidates polling onto the standard `/oauth2/token` endpoint. Service emails have been removed in favor of the agent surfacing the verification URL and `user_code` to the user, who signs in through the service's own browser-based session (reusing any existing session, SSO, MFA the service applies) and confirms the code on a service-owned page. This borrows the ceremony shape from [RFC 8628 device authorization](https://datatracker.ietf.org/doc/html/rfc8628) (`user_code`, `verification_uri`, `expires_in`, `interval`) without overloading the IANA `device_code` grant.

### Added

- `urn:workos:agent-auth:grant-type:claim` grant at `/oauth2/token` — the agent polls here with the `claim_token` for ceremony completion. Returns `authorization_pending` while waiting, `expired_token` once the window closes, and a standard OAuth token response on success, extended with `identity_assertion` + `assertion_expires` so the agent has a refresh path. A profile-specific URN so services that also implement standard RFC 8628 device authorization at the same endpoint don't collide.
- Registration responses now include a ceremony block — under `claim` for email-verification (returned with the registration) or under `claim_attempt` for anonymous (returned from `/agent/identity/claim`). Both carry `user_code`, `verification_uri`, `expires_in`, `interval`.
- `/login` — service-owned mock IdP with a cookie-bound session.
- `/claim` — service-owned, cookie-gated form where the user types the `user_code` to complete the ceremony.

### Changed

- Discovery `grant_types_supported` now lists both `urn:ietf:params:oauth:grant-type:jwt-bearer` and the new claim grant.
- `POST /agent/identity/claim/complete` is now the form-action endpoint for `/claim` — the agent no longer calls it directly. Polling moved to `/oauth2/token` with the claim grant.
- `verification_uri` carries a `claim_attempt_token` that binds the URL to a specific registration without leaking the user-typed `user_code`.
- The anonymous `email` parameter on `POST /agent/identity/claim` binds the registration to a specific signed-in account — only that user can complete the ceremony at `/claim`, preventing third-party interception of the `user_code`. The wrong-account check fires whenever `claim_email` is set, covering both anonymous and email-verification kinds.
- Anonymous claim completion **revokes** any pre-claim access_tokens the agent was holding. The canonical credential post-claim is the one returned by the claim grant.
- `POST /agent/identity/claim` accepts email-verification registrations, for initiating a new claim attempt. The supplied email must match the registration's email. Allows the agent to re-mint an expired `user_code` without re-registering. Previously this endpoint was anonymous-only and email-verification registrations had no re-initiation path.
- `/oauth2/token` (claim grant) returns `expired_token` when the `user_code` window has closed (independent of the outer claim window). Tells the agent to re-call `/agent/identity/claim` for a fresh code instead of polling `authorization_pending` indefinitely.
- Service-owned session cookie at `/login` now sets `secure: true` outside of development.

### Removed

- `/agent/identity/claim/attempt/challenge` — `user_code` is minted at ceremony start now; no separate mint step.
- `/agent/identity/claim/view` — polling moved to `/oauth2/token` with the claim grant.
- The mail surface (`mail.ts`, `routes/mail.ts`, the `.mail/` outbox directory) — the agent already has the verification URL and `user_code`, so an out-of-band email channel adds nothing.

## v0.3.0 (2026-06-03)

Switches the provider-driven invalidation channel from OIDC Back-Channel Logout to [RFC 8417](https://datatracker.ietf.org/doc/html/rfc8417) Security Event Token push delivery per [RFC 8935](https://datatracker.ietf.org/doc/html/rfc8935). Same trust path as before (issuer JWKS, jti replay protection), with a wire format and event shape that generalizes beyond revocation.

### Added

- `agent_auth.events_supported` discovery field — advertises which Security Event Token schemas the service is prepared to ingest. Currently lists `https://schemas.workos.com/events/agent/auth/identity/assertion/revoked`.

### Changed

- Endpoint: `/agent/auth/revoke` → `/agent/event/notify`.
- Discovery: `agent_auth.revocation_uri` → `agent_auth.events_endpoint`.
- JWT typ: `logout+jwt` → `secevent+jwt`; Content-Type: `application/logout+jwt` → `application/secevent+jwt`.
- Response shape: 202 Accepted on success (no body); 400 with `{ "err": "<code>", "description": "..." }` per RFC 8935 §2.4 (codes: `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`, `authentication_failed`).
- Receiver validates the `events` claim and dispatches on schema URI — only revokes for the `identity-assertion/revoked` event. Unknown schemas in the same envelope are ignored per RFC 8417 §2.2.

## v0.2.0 (2026-06-03)

Separates the identity and credential surfaces. Registration now mints a service-signed `identity_assertion` that the agent exchanges for an access_token at a standard OAuth token endpoint, instead of having `/agent/auth` issue credentials directly. Aligns the access-token issuance, revocation, and discovery surfaces with the standards they were already adjacent to (RFC 7523, RFC 7009, RFC 8414, RFC 6749).

### Added

- `/oauth2/token` ([RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) JWT-bearer grant) — agents exchange the service-signed `identity_assertion` here for a short-lived `access_token`.
- `/oauth2/revoke` ([RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)) — token revocation. Returns 200 for unknown or already-revoked tokens to prevent enumeration.
- Service-side ES256 signing key for service-minted `identity_assertion`s; JWKS published at `/.well-known/jwks.json`.

### Changed

- `/agent/auth` renamed to `/agent/identity` (and sub-paths follow).
- All three registration flows (anonymous, ID-JAG, verified-email) now return a service-signed `identity_assertion` instead of an access_token. Credentials are obtained by exchanging the assertion at `/oauth2/token`.
- Discovery (`/.well-known/oauth-authorization-server`) surfaces the top-level [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) fields (`issuer`, `token_endpoint`, `revocation_endpoint`, `grant_types_supported`) alongside the existing `agent_auth` block. Inside `agent_auth`, `register_uri` / `claim_uri` are renamed to `identity_endpoint` / `claim_endpoint`.
- Token-endpoint error responses follow the [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) envelope (`error` / `error_description`), and successful responses carry `Cache-Control: no-store` + `Pragma: no-cache` per [§5.1](https://datatracker.ietf.org/doc/html/rfc6749#section-5.1).
- [bug fix] Anonymous registrations stay on pre-claim scopes for the full duration of the claim ceremony — previously the scope cap dropped as soon as the agent called `/agent/identity/claim`, before the user had confirmed ownership.

### Removed

- `requested_credential_type` parameter from all three identity flows. The credential surface is now a separate concern (`/oauth2/token`).

## v0.1.0 (2026-05-21)

Initial proposal.
