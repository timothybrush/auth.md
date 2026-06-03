import { ports } from "shared";

const baseUrl = `http://localhost:${ports.consumer}`;
const providerUrl = `http://localhost:${ports.provider}`;

export const config = Object.freeze({
  port: ports.consumer,
  baseUrl,
  resource: `${baseUrl}/api/`,
  prmUrl: `${baseUrl}/.well-known/oauth-protected-resource`,
  trustedIssuers: [providerUrl],
  scopesSupported: ["api.read", "api.write"],
  preClaimScopes: ["api.read"],
  postClaimScopes: ["api.read", "api.write"],
  accessTokenTtlSeconds: 3600,
  /**
   * Lifetime of service-signed identity_assertions returned by /agent/identity.
   * Agents re-exchange the assertion at /oauth2/token to refresh access_tokens
   * within this window; when it expires, the agent re-calls /agent/identity.
   */
  serviceAssertionTtlSeconds: 3600,
  anonymousTtlSeconds: 86400,
  claimViewTokenTtlSeconds: 600,
  otpTtlSeconds: 600,
  clockSkewSeconds: 60,
  /** RFC 7523 JWT-bearer grant endpoint. */
  tokenEndpointPath: "/oauth2/token",
  /** RFC 7009 token revocation endpoint. */
  revocationEndpointPath: "/oauth2/revoke",
  /** Agent identity-assertion endpoint (profile extension). */
  identityEndpointPath: "/agent/identity",
  /** Claim ceremony endpoint, nested under identity. */
  claimEndpointPath: "/agent/identity/claim",
  /** RFC 8935 SET receiver path (provider-pushed identity events). */
  eventsEndpointPath: "/agent/event/notify",
  corsOrigins: [providerUrl],
  mailDir: ".mail",
  mailUrlPath: "/mail",
  keyPath: ".keys/signing-key.json",
});
