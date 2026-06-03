import { type JWTPayload, decodeProtectedHeader, jwtVerify } from "jose";
import { config } from "./config.js";
import { getPublicKey, signServiceJwt } from "./keys.js";
import { type Registration, recordJti } from "./store.js";
import { getJwks, isTrustedIssuer } from "./trust.js";
import { randomUUID } from "node:crypto";

export type VerifyError = {
  code:
    | "invalid_issuer"
    | "invalid_signature"
    | "expired"
    | "replay_detected"
    | "invalid_audience"
    | "invalid_client_id"
    | "missing_verified_email"
    | "invalid_request";
  message: string;
};

export type IdJagClaims = JWTPayload & {
  iss: string;
  sub: string;
  aud: string;
  jti: string;
  client_id?: string;
  email?: string;
  email_verified?: boolean;
  phone_number?: string;
  phone_number_verified?: boolean;
  name?: string;
  amr?: string[];
  agent_platform?: string;
  agent_context_id?: string;
};

function peekIssuer(jwt: string): string | null {
  const parts = jwt.split(".");
  if (parts.length !== 3 || !parts[1]) return null;
  try {
    const json = Buffer.from(parts[1], "base64url").toString("utf8");
    const payload = JSON.parse(json) as { iss?: unknown };
    return typeof payload.iss === "string" ? payload.iss : null;
  } catch {
    return null;
  }
}

export async function verifyIdJag(
  jwt: string,
): Promise<
  { ok: true; claims: IdJagClaims } | { ok: false; error: VerifyError }
> {
  const iss = peekIssuer(jwt);
  if (!iss || !isTrustedIssuer(iss)) {
    return {
      ok: false,
      error: {
        code: "invalid_issuer",
        message: `Issuer ${iss ?? "<missing>"} is not in the trusted providers list.`,
      },
    };
  }

  let header;
  try {
    header = decodeProtectedHeader(jwt);
  } catch {
    return {
      ok: false,
      error: { code: "invalid_request", message: "Malformed JWT header." },
    };
  }
  if (header.typ && header.typ !== "oauth-id-jag+jwt") {
    return {
      ok: false,
      error: {
        code: "invalid_request",
        message: `Unexpected typ ${String(header.typ)}; wanted oauth-id-jag+jwt.`,
      },
    };
  }

  let claims: IdJagClaims;
  try {
    const res = await jwtVerify(jwt, getJwks(iss), {
      issuer: iss,
      audience: config.baseUrl,
      typ: "oauth-id-jag+jwt",
      clockTolerance: config.clockSkewSeconds,
    });
    claims = res.payload as IdJagClaims;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/expired|exp/i.test(message)) {
      return { ok: false, error: { code: "expired", message } };
    }
    if (/audience/i.test(message)) {
      return { ok: false, error: { code: "invalid_audience", message } };
    }
    return { ok: false, error: { code: "invalid_signature", message } };
  }

  if (!claims.jti || !claims.sub) {
    return {
      ok: false,
      error: {
        code: "invalid_request",
        message: "Missing required claim (jti or sub).",
      },
    };
  }
  const replay = recordJti(
    claims.jti,
    claims.exp ?? Math.floor(Date.now() / 1000) + 300,
  );
  if (replay === "replay") {
    return {
      ok: false,
      error: {
        code: "replay_detected",
        message: `jti ${claims.jti} seen before.`,
      },
    };
  }

  if (!claims.email_verified && !claims.phone_number_verified) {
    return {
      ok: false,
      error: {
        code: "missing_verified_email",
        message: "ID-JAG must include a verified email or phone number.",
      },
    };
  }

  return { ok: true, claims };
}

export type LogoutClaims = JWTPayload & {
  iss: string;
  sub: string;
  aud: string;
  jti: string;
  events: Record<string, unknown>;
};

export async function verifyLogoutJwt(
  jwt: string,
): Promise<
  { ok: true; claims: LogoutClaims } | { ok: false; error: VerifyError }
> {
  const iss = peekIssuer(jwt);
  if (!iss || !isTrustedIssuer(iss)) {
    return {
      ok: false,
      error: {
        code: "invalid_issuer",
        message: `Issuer ${iss ?? "<missing>"} is not in the trusted providers list.`,
      },
    };
  }
  try {
    const res = await jwtVerify(jwt, getJwks(iss), {
      issuer: iss,
      audience: config.baseUrl,
      typ: "logout+jwt",
      clockTolerance: config.clockSkewSeconds,
    });
    const claims = res.payload as LogoutClaims;
    if (!claims.jti || !claims.sub) {
      return {
        ok: false,
        error: {
          code: "invalid_request",
          message: "Missing required claim (jti or sub).",
        },
      };
    }
    const replay = recordJti(
      claims.jti,
      claims.exp ?? Math.floor(Date.now() / 1000) + 300,
    );
    if (replay === "replay") {
      return {
        ok: false,
        error: {
          code: "replay_detected",
          message: `jti ${claims.jti} seen before.`,
        },
      };
    }
    return { ok: true, claims };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: { code: "invalid_signature", message } };
  }
}

export type ServiceAssertionClaims = JWTPayload & {
  iss: string;
  sub: string;
  aud: string;
  jti: string;
  email?: string;
  email_verified?: boolean;
  amr?: string[];
};

/**
 * Mint a service-signed identity_assertion bound to a registration. The
 * agent presents this at /oauth2/token (RFC 7523 JWT-bearer) to obtain an
 * access_token. `sub` is the registration id so the token endpoint can
 * resolve back to the registration's state on exchange.
 */
export async function signServiceIdJag(input: {
  registration: Registration;
  email?: string;
  emailVerified?: boolean;
  amr?: string[];
}): Promise<{ jwt: string; expiresAt: Date }> {
  const payload: Record<string, unknown> = {
    iss: config.baseUrl,
    sub: input.registration.id,
    aud: config.baseUrl,
    jti: `jti_${randomUUID()}`,
  };
  if (input.email) payload.email = input.email;
  if (input.emailVerified !== undefined) {
    payload.email_verified = input.emailVerified;
  }
  if (input.amr) payload.amr = input.amr;
  return signServiceJwt(
    payload,
    "oauth-id-jag+jwt",
    config.serviceAssertionTtlSeconds,
  );
}

export async function verifyServiceIdJag(
  jwt: string,
): Promise<
  | { ok: true; claims: ServiceAssertionClaims }
  | { ok: false; error: VerifyError }
> {
  let header;
  try {
    header = decodeProtectedHeader(jwt);
  } catch {
    return {
      ok: false,
      error: { code: "invalid_request", message: "Malformed JWT header." },
    };
  }
  if (header.typ && header.typ !== "oauth-id-jag+jwt") {
    return {
      ok: false,
      error: {
        code: "invalid_request",
        message: `Unexpected typ ${String(header.typ)}; wanted oauth-id-jag+jwt.`,
      },
    };
  }
  try {
    const publicKey = await getPublicKey();
    const res = await jwtVerify(jwt, publicKey, {
      issuer: config.baseUrl,
      audience: config.baseUrl,
      typ: "oauth-id-jag+jwt",
      clockTolerance: config.clockSkewSeconds,
    });
    const claims = res.payload as ServiceAssertionClaims;
    if (!claims.jti || !claims.sub) {
      return {
        ok: false,
        error: {
          code: "invalid_request",
          message: "Missing required claim (jti or sub).",
        },
      };
    }
    return { ok: true, claims };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/expired|exp/i.test(message)) {
      return { ok: false, error: { code: "expired", message } };
    }
    if (/audience/i.test(message)) {
      return { ok: false, error: { code: "invalid_audience", message } };
    }
    return { ok: false, error: { code: "invalid_signature", message } };
  }
}
