# auth.md Changelog

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
