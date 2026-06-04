import express, { Router } from "express";
import { config } from "../config.js";
import { matchOrProvision } from "../matcher.js";
import {
  ASSERTION_TYPES,
  agentAuthBody,
  claimBody,
  parseBody,
} from "../schemas.js";
import {
  createAnonymousRegistration,
  createEmailVerificationRegistration,
  findOrCreateIdJagRegistration,
  findRegistrationByClaimHash,
  recordClaimAttempt,
  revokeForDelegation,
  sha256Hex,
} from "../store.js";
import {
  type VerifyError,
  signServiceIdJag,
  verifyIdJag,
  verifySecEventJwt,
} from "../verify.js";

/*
 * Agent-facing endpoints. The user-facing claim ceremony — the page where
 * the user signs in and types the user_code — lives in routes/login.ts and
 * routes/claim.ts. The agent never reaches those; it polls /oauth2/token
 * with the claim grant (urn:workos:agent-auth:grant-type:claim). See
 * routes/token.ts.
 *
 * The ceremony block returned in registration responses (under `claim` for
 * email-verification, `claim_attempt` for anonymous) borrows RFC 8628
 * device-authorization shape, with `claim_attempt_token` embedded in
 * `verification_uri` so the URL identifies the registration without
 * leaking the user-typed `user_code`.
 */

export const agentAuthRouter = Router();

agentAuthRouter.post(config.identityEndpointPath, async (req, res) => {
  const parsed = parseBody(agentAuthBody, req.body);
  if (!parsed.ok) {
    res.status(400).json({ error: "invalid_request", message: parsed.message });
    return;
  }

  if (parsed.value.type === "identity_assertion") {
    if (parsed.value.assertion_type === ASSERTION_TYPES.EMAIL_ASSERTION) {
      return handleEmailAssertion(parsed.value, res);
    }
    return handleIdJagAssertion(parsed.value, res);
  }

  const { registration, claimTokenPlaintext } = createAnonymousRegistration();
  const { jwt, expiresAt } = await signServiceIdJag({ registration });
  console.log(
    `[agent-auth] registered anonymous agent registration=${registration.id}`,
  );
  res.json({
    registration_id: registration.id,
    registration_type: "anonymous",
    identity_assertion: jwt,
    assertion_expires: expiresAt.toISOString(),
    pre_claim_scopes: config.preClaimScopes,
    claim_url: `${config.baseUrl}${config.claimEndpointPath}`,
    claim_token: claimTokenPlaintext,
    claim_token_expires: registration.claim!.expires_at.toISOString(),
    post_claim_scopes: config.postClaimScopes,
  });
});

async function handleIdJagAssertion(
  body: { assertion: string },
  res: express.Response,
): Promise<void> {
  const verified = await verifyIdJag(body.assertion);
  if (!verified.ok) {
    res
      .status(400)
      .json({ error: verified.error.code, message: verified.error.message });
    return;
  }
  const { claims } = verified;
  const { user } = matchOrProvision(claims);

  /*
   * Ensure a registration exists for this (iss, sub, aud) so future
   * credential lifecycle (revocation, audit, /token refresh) has a durable
   * identity to anchor to. Idempotent across repeat presentations.
   */
  const registration = findOrCreateIdJagRegistration({
    iss: claims.iss,
    sub: claims.sub,
    aud: claims.aud,
    userId: user.id,
  });

  const { jwt, expiresAt } = await signServiceIdJag({
    registration,
    email: claims.email,
    emailVerified: claims.email_verified,
    amr: claims.amr,
  });
  console.log(
    `[agent-auth] issued identity_assertion to user=${user.id} via iss=${claims.iss} sub=${claims.sub} registration=${registration.id}`,
  );
  res.json({
    registration_id: registration.id,
    registration_type: "agent-provider",
    identity_assertion: jwt,
    assertion_expires: expiresAt.toISOString(),
    scopes: config.scopesSupported,
  });
}

async function handleEmailAssertion(
  body: { assertion: string },
  res: express.Response,
): Promise<void> {
  const {
    registration,
    claimTokenPlaintext,
    claimViewTokenPlaintext,
    userCode,
    userCodeExpiresAt,
  } = createEmailVerificationRegistration({ email: body.assertion });

  console.log(
    `[agent-auth] email-verification registration=${registration.id} email=${body.assertion}`,
  );

  res.json({
    registration_id: registration.id,
    registration_type: "email-verification",
    claim_url: `${config.baseUrl}${config.claimEndpointPath}`,
    claim_token: claimTokenPlaintext,
    claim_token_expires: registration.claim!.expires_at.toISOString(),
    post_claim_scopes: config.postClaimScopes,
    claim: buildCeremonyBlock({
      claimViewTokenPlaintext,
      userCode,
      userCodeExpiresAt,
    }),
  });
}

/*
 * Initiates or re-mints a claim ceremony. Two registration kinds reach here:
 *   - anonymous: first initiation (binds the email) or refresh (after the
 *     user_code window closed before the user could complete).
 *   - email_verification: refresh only (the initial ceremony was minted at
 *     /agent/identity); the supplied email must match the registration.
 */
agentAuthRouter.post(config.claimEndpointPath, async (req, res) => {
  const parsed = parseBody(claimBody, req.body);
  if (!parsed.ok) {
    res.status(400).json({ error: "invalid_request", message: parsed.message });
    return;
  }
  const registration = findRegistrationByClaimHash(
    sha256Hex(parsed.value.claim_token),
  );
  if (!registration) {
    res.status(401).json({
      error: "invalid_claim_token",
      message: "The claim token is invalid.",
    });
    return;
  }
  if (registration.kind === "id_jag") {
    res.status(409).json({
      error: "claimed_or_in_flight",
      message: "ID-JAG registrations do not require a claim ceremony.",
    });
    return;
  }
  if (registration.status === "expired") {
    res
      .status(410)
      .json({ error: "claim_expired", message: "Registration has expired." });
    return;
  }
  if (registration.status === "claimed") {
    res.status(409).json({
      error: "claimed_or_in_flight",
      message: "This registration has already been claimed.",
    });
    return;
  }
  if (
    registration.kind === "email_verification" &&
    registration.claim?.email !== parsed.value.email
  ) {
    res.status(400).json({
      error: "email_mismatch",
      message:
        "The supplied email does not match the registration's bound email.",
    });
    return;
  }

  /*
   * Mint a fresh ceremony (new claim_attempt_token + new user_code). For
   * anonymous this binds the supplied email; for email-verification it refreshes
   * an expired user_code without changing the bound email. Any prior URL
   * stops working.
   */
  const fresh = recordClaimAttempt(registration, parsed.value.email);
  const attempt = registration.claim!.attempt!;

  console.log(
    `[agent-auth] claim initiated for registration=${registration.id} to=${parsed.value.email}`,
  );

  res.json({
    registration_id: registration.id,
    claim_attempt_id: attempt.id,
    status: "initiated",
    expires_at: attempt.view_expires_at.toISOString(),
    claim_attempt: buildCeremonyBlock({
      claimViewTokenPlaintext: fresh.claimViewTokenPlaintext,
      userCode: fresh.userCode,
      userCodeExpiresAt: fresh.userCodeExpiresAt,
    }),
  });
});

/*
 * Polling moved to /oauth2/token with grant_type=urn:workos:agent-auth:
 * grant-type:claim. The agent posts its claim_token there; while pending
 * the response is { error: "authorization_pending" }, on completion the
 * standard token response is returned plus an `identity_assertion`
 * extension so the agent has a refresh path via jwt-bearer. See
 * routes/token.ts.
 */

function buildCeremonyBlock(input: {
  claimViewTokenPlaintext: string;
  userCode: string;
  userCodeExpiresAt: Date;
}): Record<string, unknown> {
  return {
    user_code: input.userCode,
    expires_in: secondsUntil(input.userCodeExpiresAt),
    verification_uri: buildVerificationUri(input.claimViewTokenPlaintext),
    interval: config.pollIntervalSeconds,
  };
}

/*
 * Routes the user through /login first (mock IdP). `return_to` carries the
 * /claim path with the binding token. The agent never resolves this URL —
 * the user opens it in their browser.
 */
function buildVerificationUri(claimAttemptToken: string): string {
  const claimPath = `/claim?claim_attempt_token=${encodeURIComponent(claimAttemptToken)}`;
  return `${config.baseUrl}/login?return_to=${encodeURIComponent(claimPath)}`;
}

function secondsUntil(when: Date): number {
  return Math.max(0, Math.floor((when.getTime() - Date.now()) / 1000));
}

/*
 * RFC 8935 SET receiver. Providers POST a signed Security Event Token
 * (RFC 8417) here to invalidate the registration and credentials tied to
 * the (iss, sub, aud) triple in the SET. Response shape follows RFC 8935
 * §2.4 — 202 Accepted with no body on success; 400 with { err, description }
 * on failure (note: "err"/"description", not "error"/"message").
 */
agentAuthRouter.post(
  config.eventsEndpointPath,
  express.text({ type: "application/secevent+jwt" }),
  async (req, res) => {
    const token = typeof req.body === "string" ? req.body.trim() : "";
    if (!token) {
      res.status(400).json({
        err: "invalid_request",
        description:
          "Expected JWT body with Content-Type application/secevent+jwt.",
      });
      return;
    }
    const verified = await verifySecEventJwt(token);
    if (!verified.ok) {
      const { err, description } = mapSecEventError(verified.error);
      res.status(400).json({ err, description });
      return;
    }
    /*
     * Dispatch on the SET's `events` schema URIs. We only handle the
     * identity-assertion revocation event today; per RFC 8417 §2.2, any
     * unknown schemas in the same envelope are silently ignored (we still
     * 202 the delivery — the SET was well-formed, we just had nothing to
     * do for it).
     */
    const schemas = Object.keys(verified.claims.events);
    if (schemas.includes(IDENTITY_ASSERTION_REVOKED_SCHEMA)) {
      const count = revokeForDelegation(
        verified.claims.iss,
        verified.claims.sub,
        verified.claims.aud,
      );
      console.log(
        `[agent-auth] revoked ${count} credentials for iss=${verified.claims.iss} sub=${verified.claims.sub}`,
      );
    } else {
      console.log(
        `[agent-auth] SET from ${verified.claims.iss} carried no recognized events (${schemas.join(", ")}); no-op`,
      );
    }
    res.status(202).end();
  },
);

export const IDENTITY_ASSERTION_REVOKED_SCHEMA =
  "https://schemas.workos.com/events/agent/auth/identity/assertion/revoked";

/**
 * Map our internal verify error codes onto the SET delivery error codes
 * defined in RFC 8935 §2.4: invalid_request, invalid_key, invalid_issuer,
 * invalid_audience, authentication_failed.
 */
function mapSecEventError(error: VerifyError): {
  err: string;
  description: string;
} {
  switch (error.code) {
    case "invalid_issuer":
      return { err: "invalid_issuer", description: error.message };
    case "invalid_audience":
      return { err: "invalid_audience", description: error.message };
    case "invalid_signature":
    case "expired":
      return { err: "authentication_failed", description: error.message };
    default:
      return { err: "invalid_request", description: error.message };
  }
}
