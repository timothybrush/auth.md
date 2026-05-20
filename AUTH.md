# auth.md

You are an agent. This service supports **agentic registration**: discover → register → (claim if needed) → call API → handle revocation. Follow the steps in order; do not skip ahead.

Examples use placeholder hosts: `https://api.service.com` (the resource server hosting the API you want to call) and `https://auth.service.com` (the authorization server that handles registration). Real services substitute their own.

## Step 1 — Discover

Discovery is two hops — you may have already done this.

The 401 response that pointed you here also carries a `WWW-Authenticate` header with the PRM URL:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://api.service.com/.well-known/oauth-protected-resource"
```

Pull the `resource_metadata` value from that header and fetch it (1a). If you don't have the 401 in hand, the conventional path on the resource server is `/.well-known/oauth-protected-resource`.

### 1a. Fetch the Protected Resource Metadata

```http
GET /.well-known/oauth-protected-resource
```

Response shape:

```json
{
  "resource": "https://api.service.com/",
  "resource_name": "Service",
  "resource_logo_uri": "https://service.com/logo.png",
  "authorization_servers": ["https://auth.service.com/"],
  "scopes_supported": ["api.read", "api.write"],
  "bearer_methods_supported": ["header"]
}
```

What each field tells you:

- `resource` — the canonical URL of the API you're trying to call. Use this as the `aud` when minting an ID-JAG.
- `resource_name` / `resource_logo_uri` — display name and logo for the service. Surface these to the user when asking for consent.
- `authorization_servers` — base URLs of the OAuth Authorization Server(s) for this resource. The `agent_auth` block lives on one of these (see 1b).
- `scopes_supported` — scopes the resource server understands. The credential you receive will be scoped to some subset; you don't request specific scopes during registration.
- `bearer_methods_supported` — how you'll send the credential in Step 5 (`"header"` = `Authorization: Bearer …`).

### 1b. Fetch the Authorization Server metadata

```http
GET <authorization_servers[0]>/.well-known/oauth-authorization-server
```

Response shape:

```json
{
  "resource": "https://api.service.com/",
  "authorization_servers": ["https://auth.service.com/"],
  "scopes_supported": ["api.read", "api.write"],
  "bearer_methods_supported": ["header"],
  "agent_auth": {
    "skill": "https://service.com/auth.md",
    "register_uri": "https://auth.service.com/agent/auth",
    "claim_uri": "https://auth.service.com/agent/auth/claim",
    "revocation_uri": "https://auth.service.com/agent/auth/revoke",
    "identity_types_supported": ["anonymous", "identity_assertion"],
    "anonymous": {
      "credential_types_supported": ["api_key"]
    },
    "identity_assertion": {
      "assertion_types_supported": [
        "urn:ietf:params:oauth:token-type:id-jag",
        "verified_email"
      ],
      "credential_types_supported": ["access_token", "api_key"]
    },
    "events_supported": [
      "https://schemas.workos.com/events/agent/auth/identity/assertion/revoked"
    ]
  }
}
```

The outer fields restate the PRM. The `agent_auth` block is the part written for you — read it in full. Every field there is relevant:

- `skill` — the URL of this document.
- `register_uri` — where you POST to register (Step 3).
- `claim_uri` — where you POST the claim invite (Step 4, anonymous flow only).
- `revocation_uri` — where the provider POSTs a `logout+jwt` to revoke your credential. You don't call this; it tells you what to expect.
- `identity_types_supported` — which registration methods this service accepts. Pick yours from Step 2.
- `anonymous.credential_types_supported` — credential shapes available when registering anonymously.
- `identity_assertion.assertion_types_supported` — which assertion types this service accepts (ID-JAG, verified email, etc.).
- `identity_assertion.credential_types_supported` — credential shapes available when registering with an assertion.
- `events_supported` — security event schemas this service can ingest (currently revocation). Informational; you don't act on these directly.

## Step 2 — Pick a method

Use this decision tree:

1. **You have a session tied to a user identity and can exchange it for an ID-JAG, audience-bound to this service** → [identity_assertion + id-jag](#identity_assertion--id-jag).
2. **You have only the user's email** → [identity_assertion + email](#identity_assertion--email). Claim ceremony required.
3. **You have neither** → [anonymous](#anonymous). Claim ceremony optional; deferred until the user wants to take ownership.

Before sending: cross-check your choice against the `agent_auth` block. If the matching `*_supported` array doesn't list your method, this service won't accept that registration shape — pick another or stop.

## Step 3 — Register

### identity_assertion + id-jag

```http
POST /agent/auth
Content-Type: application/json

{
  "type": "identity_assertion",
  "assertion_type": "urn:ietf:params:oauth:token-type:id-jag",
  "assertion": "<your ID-JAG JWT>",
  "requested_credential_type": "access_token"
}
```

Response (200):

```json
{
  "registration_id": "reg_...",
  "registration_type": "agent-provider",
  "credential_type": "access_token",
  "credential": "<token>",
  "credential_expires": "2026-05-04T13:00:00.000Z",
  "scopes": ["..."]
}
```

Extract `credential`. Go to [Step 5](#step-5--use-the-credential).

### identity_assertion + email

```http
POST /agent/auth
Content-Type: application/json

{
  "type": "identity_assertion",
  "assertion_type": "verified_email",
  "assertion": "user@example.com",
  "requested_credential_type": "api_key"
}
```

Response (200):

```json
{
  "registration_id": "reg_...",
  "registration_type": "email-verification",
  "claim_url": "https://auth.service.com/agent/auth/claim",
  "claim_token": "clm_...",
  "claim_token_expires": "2026-05-21T17:31:25.994Z",
  "post_claim_scopes": ["api.read", "api.write"]
}
```

There is no credential yet. The service has already emailed the user. Keep `claim_token` and go to [Step 4](#step-4--claim-ceremony).

### anonymous

```http
POST /agent/auth
Content-Type: application/json

{
  "type": "anonymous",
  "requested_credential_type": "api_key"
}
```

Response (200):

```json
{
  "registration_id": "reg_...",
  "registration_type": "anonymous",
  "credential_type": "api_key",
  "credential": "sk_test_...",
  "credential_expires": null,
  "scopes": ["api.read"],
  "claim_url": "https://auth.service.com/agent/auth/claim",
  "claim_token": "clm_...",
  "claim_token_expires": "2026-05-21T17:26:32.915Z",
  "post_claim_scopes": ["api.read", "api.write"]
}
```

You have a usable credential immediately at pre-claim scopes. If you also want a human to take ownership and unlock `post_claim_scopes`, go to [Step 4](#step-4--claim-ceremony). Otherwise skip to [Step 5](#step-5--use-the-credential).

## Step 4 — Claim ceremony

The end goal: get the user to read a 6-digit OTP back to you.

### 4a. Trigger the claim email (anonymous only)

Skip this for `email` registrations — the email was sent during Step 3.

```http
POST /agent/auth/claim
Content-Type: application/json

{
  "claim_token": "clm_...",
  "email": "user@example.com"
}
```

Response (200):

```json
{
  "registration_id": "reg_...",
  "claim_attempt_id": "...",
  "status": "initiated",
  "expires_at": "..."
}
```

### 4b. Wait for the user's OTP

The user receives an email, clicks the link, sees a 6-digit OTP, reads it back to you. Surface this in your agent UI:

> "Check your email and tell me the 6-digit code."

### 4c. Submit the OTP

```http
POST /agent/auth/claim/complete
Content-Type: application/json

{
  "claim_token": "clm_...",
  "otp": "123456"
}
```

Response on success (anonymous):

```json
{ "registration_id": "reg_...", "status": "claimed" }
```

Your existing pre-claim API key keeps working — its scope set is upgraded in place. No new credential is issued.

Response on success (email-verification):

```json
{
  "registration_id": "reg_...",
  "status": "claimed",
  "credential_type": "access_token",
  "credential": "<token>",
  "credential_expires": "...",
  "scopes": ["..."]
}
```

Extract `credential`.

## Step 5 — Use the credential

Whether `access_token` or `api_key`, present as a bearer token:

```http
GET /api/some-resource
Authorization: Bearer <credential>
```

- `access_token` from an ID-JAG: when it expires, mint a **fresh** ID-JAG and re-register. There is no refresh flow.
- `access_token` from a claim ceremony: when it expires, re-run the ceremony or present a fresh assertion.
- `api_key`: typically no expiry (`credential_expires: null`), but still subject to revocation.

If you get a 401 on a previously-working credential: drop it, restart at [Step 1](#step-1--discover). Do not stash the credential and retry.

## Errors

| Code                          | Where                        | What to do                                                                             |
| ----------------------------- | ---------------------------- | -------------------------------------------------------------------------------------- |
| `invalid_signature`           | `/agent/auth` (ID-JAG)       | Signature didn't verify. Mint a fresh ID-JAG.                                          |
| `replay_detected`             | `/agent/auth` (ID-JAG)       | `jti` already used. Mint a fresh ID-JAG with a new `jti`.                              |
| `audience_mismatch`           | `/agent/auth` (ID-JAG)       | `aud` wrong. Mint with the correct `aud` (this service's AS base URL).                 |
| `credential_expired`          | `/agent/auth` (ID-JAG)       | ID-JAG `exp` is past. Mint a fresh one.                                                |
| `anonymous_not_enabled`       | `/agent/auth`                | This service doesn't accept anonymous. Pick another method from Step 2.                |
| `verified_email_not_enabled`  | `/agent/auth`                | Email verification disabled here. Pick another method.                                 |
| `issuer_not_enabled`          | `/agent/auth`                | Provider not on this service's trust list. Pick another method.                        |
| `unsupported_credential_type` | `/agent/auth`                | Requested credential not supported for this method. Re-read AS metadata and adjust.    |
| `rate_limited` (429)          | any                          | Back off and retry.                                                                    |
| `invalid_claim_token`         | `/agent/auth/claim/complete` | `claim_token` wrong or expired. Restart at Step 3.                                     |
| `otp_invalid`                 | `/agent/auth/claim/complete` | OTP mismatch. Ask the user to re-read the code.                                        |
| `otp_expired`                 | `/agent/auth/claim/complete` | OTP window passed. Re-trigger the claim email (Step 4a) or restart at Step 3.          |
| `claim_expired`               | `/agent/auth/claim/complete` | The whole registration expired. Restart at Step 3.                                     |
| `previously_claimed`          | `/agent/auth/claim/complete` | Someone already finished this claim. Restart at Step 3 if you need a fresh credential. |

## Revocation

You do not initiate revocation yourself. Two paths exist:

- **Provider-driven (ID-JAG flows)**: the provider that minted your ID-JAG can POST a `logout+jwt` to this service's `revocation_uri`. Your credential will be invalidated. You discover this on the next API call returning 401 — restart at [Step 1](#step-1--discover).
- **Email / anonymous flows**: there is no agent-facing revoke endpoint. On a 401 for a previously-working credential, drop it and restart at Step 1.
