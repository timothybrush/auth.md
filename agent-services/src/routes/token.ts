import express, { Router } from "express";
import { config } from "../config.js";
import {
  parseBody,
  revocationEndpointBody,
  tokenEndpointBody,
} from "../schemas.js";
import {
  findRegistrationById,
  issueAccessToken,
  revokeCredential,
} from "../store.js";
import { verifyServiceIdJag } from "../verify.js";

/*
 * OAuth credential surface for the agent-auth profile.
 *
 * /oauth2/token (RFC 7523 JWT-bearer) — exchanges a service-signed
 * identity_assertion for an access_token. The assertion's `sub` resolves to
 * a registration; the scope set is derived from the registration's state
 * (pre-claim scopes for an unclaimed anonymous registration, full scopes
 * once claimed or for any identity-bound registration).
 *
 * /oauth2/revoke (RFC 7009) — kills a single access_token by value. 200 on
 * success, idempotent, no enumeration leakage on unknown tokens.
 */

export const tokenRouter = Router();

const formParser = express.urlencoded({ extended: false });

type OAuthErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "invalid_scope";

/**
 * Per RFC 6749 §5.1, the AS MUST set Cache-Control: no-store and Pragma:
 * no-cache on responses containing tokens or other sensitive data. Apply to
 * every response from the token endpoint, success and error alike.
 */
function setOAuthHeaders(res: express.Response): void {
  res.set("Cache-Control", "no-store");
  res.set("Pragma", "no-cache");
}

/**
 * RFC 6749 §5.2 error envelope. Status is 400 by default; invalid_client
 * MAY be 401 (and SHOULD be 401 if the client tried to authenticate via the
 * Authorization header — not relevant for this profile, which is bearer-
 * assertion only).
 */
function oauthError(
  res: express.Response,
  code: OAuthErrorCode,
  description: string,
): void {
  const status = code === "invalid_client" ? 401 : 400;
  setOAuthHeaders(res);
  res.status(status).json({ error: code, error_description: description });
}

tokenRouter.post(config.tokenEndpointPath, formParser, async (req, res) => {
  /*
   * RFC 6749 §5.2 names a dedicated error code for grant_type problems.
   * Check it before the rest of the body so we don't collapse the wrong-
   * grant case into invalid_request.
   */
  const grantType =
    typeof req.body?.grant_type === "string" ? req.body.grant_type : undefined;
  if (grantType !== "urn:ietf:params:oauth:grant-type:jwt-bearer") {
    return oauthError(
      res,
      "unsupported_grant_type",
      grantType
        ? `Unsupported grant_type: ${grantType}.`
        : "Missing grant_type.",
    );
  }

  const parsed = parseBody(tokenEndpointBody, req.body);
  if (!parsed.ok) return oauthError(res, "invalid_request", parsed.message);

  const verified = await verifyServiceIdJag(parsed.value.assertion);
  if (!verified.ok) {
    return oauthError(res, "invalid_grant", verified.error.message);
  }

  const registration = findRegistrationById(verified.claims.sub);
  if (!registration) {
    return oauthError(
      res,
      "invalid_grant",
      `No registration found for sub=${verified.claims.sub}.`,
    );
  }
  if (registration.status === "expired") {
    return oauthError(
      res,
      "invalid_grant",
      `The registration has expired. Re-register at ${config.identityEndpointPath}.`,
    );
  }

  /*
   * Anonymous registrations stay on pre-claim scopes until a human has
   * actually confirmed ownership (status: claimed). `unclaimed` and
   * `pending_claim` both predate confirmation — the latter means the
   * agent has kicked off a claim ceremony but the user hasn't yet
   * approved it, so the pre-claim cap still applies. Email-verification
   * registrations always reach /oauth2/token via a post-claim
   * identity_assertion (the registration is bound to a user before the
   * assertion is minted), so they get the full set.
   */
  const scope =
    registration.kind === "anonymous" && registration.status !== "claimed"
      ? config.preClaimScopes
      : config.scopesSupported;

  const credential = issueAccessToken({
    userId: registration.user_id,
    scope,
    source: sourceForRegistrationKind(registration.kind),
    iss: registration.id_jag?.iss,
    sub: registration.id_jag?.sub,
    aud: registration.id_jag?.aud,
    registrationId: registration.id,
  });

  console.log(
    `[token] issued access_token for registration=${registration.id} status=${registration.status} scopes=${scope.join(",")}`,
  );

  const expiresIn = credential.expires_at
    ? Math.max(
        0,
        Math.floor((credential.expires_at.getTime() - Date.now()) / 1000),
      )
    : config.accessTokenTtlSeconds;

  setOAuthHeaders(res);
  res.json({
    access_token: credential.token,
    token_type: "Bearer",
    expires_in: expiresIn,
    scope: scope.join(" "),
  });
});

tokenRouter.post(config.revocationEndpointPath, formParser, (req, res) => {
  const parsed = parseBody(revocationEndpointBody, req.body);
  if (!parsed.ok) {
    return oauthError(res, "invalid_request", parsed.message);
  }
  /*
   * RFC 7009 §2.2: unknown / already-revoked tokens return 200 to prevent
   * enumeration. We only error on a malformed body (missing token field),
   * which is an integration bug, not a probe.
   */
  const revoked = revokeCredential(parsed.value.token);
  console.log(
    `[token] revocation ${revoked ? "applied" : "no-op"} for token=${parsed.value.token.slice(0, 8)}...`,
  );
  setOAuthHeaders(res);
  res.status(200).end();
});

function sourceForRegistrationKind(
  kind: "anonymous" | "email_verification" | "id_jag",
): "anonymous" | "email_verification" | "identity_assertion" {
  if (kind === "id_jag") return "identity_assertion";
  return kind;
}
