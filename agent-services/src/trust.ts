import { createRemoteJWKSet } from "jose";
import { config } from "./config.js";

type Jwks = ReturnType<typeof createRemoteJWKSet>;

const jwksCache = new Map<string, Jwks>();

export function isTrustedIssuer(iss: string): boolean {
  return config.trustedIssuers.some((entry) => entry.iss === iss);
}

/**
 * Service-controlled display name for a trusted issuer, rendered on the
 * step-up confirmation page so the user sees "Cursor is asking to link…"
 * rather than a bare URL. Falls back to the iss URL if the issuer isn't on
 * the trust list (shouldn't happen in practice — verifyIdJag rejects
 * untrusted issuers up front).
 */
export function trustedIssuerDisplayName(iss: string): string {
  const entry = config.trustedIssuers.find((e) => e.iss === iss);
  return entry?.displayName ?? iss;
}

export function getJwks(iss: string): Jwks {
  let jwks = jwksCache.get(iss);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${iss}/.well-known/jwks.json`));
    jwksCache.set(iss, jwks);
  }
  return jwks;
}
