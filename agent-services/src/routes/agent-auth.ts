import express, { Router } from "express";
import { config } from "../config.js";
import { sendClaimViewEmail } from "../mail.js";
import { matchOrProvision } from "../matcher.js";
import {
  ASSERTION_TYPES,
  agentAuthBody,
  claimBody,
  claimCompleteBody,
  generateOtpBody,
  parseBody,
} from "../schemas.js";
import {
  completeClaim,
  createAnonymousRegistration,
  createEmailVerificationRegistration,
  findOrCreateIdJagRegistration,
  findRegistrationByClaimHash,
  findRegistrationByClaimViewHash,
  generateOtpForRegistration,
  recordAnonymousClaimAttempt,
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
 * Agent-facing endpoints implementing the OTP-exchange flavor of the
 * agent-auth spec. The user-facing /agent/identity/claim/view endpoint at the
 * bottom of this file is also part of the spec — it's where the email link
 * lands and where the OTP is rendered.
 *
 * All three flows (anonymous, identity_assertion+id_jag, identity_assertion+
 * email) terminate by returning a service-signed identity_assertion. The
 * agent then exchanges that assertion at /oauth2/token (RFC 7523 JWT-bearer)
 * for an access_token. No credentials are issued here.
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
  const { registration, claimTokenPlaintext, claimViewTokenPlaintext } =
    createEmailVerificationRegistration({ email: body.assertion });

  /*
   * Email-verification registrations bundle the claim ceremony — we send
   * the OTP-view email immediately. The agent skips /agent/identity/claim
   * and polls /complete with the OTP the user reads back.
   */
  const viewUrl = `${config.baseUrl}${config.claimEndpointPath}/view?token=${encodeURIComponent(claimViewTokenPlaintext)}`;
  await sendClaimViewEmail({
    registrationId: registration.id,
    recipientEmail: body.assertion,
    viewUrl,
    expiresAt: registration.claim!.attempt!.view_expires_at,
  });

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
  });
}

/*
 * Anonymous-only entry point. Email-verification registrations skip this —
 * their claim attempt is created in /agent/identity itself.
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
  if (registration.kind !== "anonymous") {
    res.status(409).json({
      error: "claimed_or_in_flight",
      message:
        "Email-verification registrations do not require an explicit /claim call.",
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

  /*
   * Idempotent: if a claim attempt is already in flight (same email, view
   * window still open), echo current state without resending the email. A
   * same-email retry after the view window expires falls through and mints
   * a fresh attempt below.
   */
  const inflight = registration.claim?.attempt;
  if (
    registration.status === "pending_claim" &&
    registration.claim?.email === parsed.value.email &&
    inflight &&
    inflight.view_expires_at.getTime() > Date.now()
  ) {
    res.json({
      registration_id: registration.id,
      claim_attempt_id: inflight.id,
      status: "initiated",
      expires_at: inflight.view_expires_at.toISOString(),
    });
    return;
  }

  const claimViewTokenPlaintext = recordAnonymousClaimAttempt(
    registration,
    parsed.value.email,
  );
  const attempt = registration.claim!.attempt!;
  const viewUrl = `${config.baseUrl}${config.claimEndpointPath}/view?token=${encodeURIComponent(claimViewTokenPlaintext)}`;
  await sendClaimViewEmail({
    registrationId: registration.id,
    recipientEmail: parsed.value.email,
    viewUrl,
    expiresAt: attempt.view_expires_at,
  });

  console.log(
    `[agent-auth] claim initiated for registration=${registration.id} to=${parsed.value.email}`,
  );

  res.json({
    registration_id: registration.id,
    claim_attempt_id: attempt.id,
    status: "initiated",
    expires_at: attempt.view_expires_at.toISOString(),
  });
});

/* Exchanges a claim_attempt_token for an OTP. */
agentAuthRouter.post(
  `${config.claimEndpointPath}/attempt/challenge`,
  (req, res) => {
    const parsed = parseBody(generateOtpBody, req.body);
    if (!parsed.ok) {
      res
        .status(400)
        .json({ error: "invalid_request", message: parsed.message });
      return;
    }
    const registration = findRegistrationByClaimViewHash(
      sha256Hex(parsed.value.claim_attempt_token),
    );
    if (!registration) {
      res.status(410).json({
        error: "claim_superseded",
        message: "The claim attempt token is invalid or has been superseded.",
      });
      return;
    }
    if (registration.status === "claimed") {
      res
        .status(409)
        .json({ error: "claim_completed", message: "Already claimed." });
      return;
    }
    const attempt = registration.claim?.attempt;
    if (!attempt || attempt.view_expires_at.getTime() < Date.now()) {
      res
        .status(410)
        .json({ error: "claim_expired", message: "Claim window has closed." });
      return;
    }
    const { otp, expiresAt } = generateOtpForRegistration(registration);
    console.log(
      `[agent-auth] generated otp for registration=${registration.id}`,
    );
    res.json({
      type: "otp",
      challenge: otp,
      expires_at: expiresAt.toISOString(),
    });
  },
);

agentAuthRouter.post(
  `${config.claimEndpointPath}/complete`,
  async (req, res) => {
    const parsed = parseBody(claimCompleteBody, req.body);
    if (!parsed.ok) {
      res
        .status(400)
        .json({ error: "invalid_request", message: parsed.message });
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

    const result = completeClaim(registration, parsed.value.otp);
    if (!result.ok) {
      const status = pickStatusForCompleteError(result.error);
      res.status(status).json({
        error: result.error,
        message: humanCompleteError(result.error),
      });
      return;
    }

    console.log(
      `[agent-auth] claim completed for registration=${result.registration.id}`,
    );

    /*
     * Anonymous: no fresh assertion — the original is still valid; the agent
     * re-exchanges it at /oauth2/token to pick up the upgraded post-claim
     * scope set on its access_token.
     *
     * Email-verification: mint a fresh service-signed identity_assertion the
     * agent exchanges at /oauth2/token for its first access_token.
     */
    if (result.registration.kind === "anonymous") {
      res.json({ registration_id: result.registration.id, status: "claimed" });
      return;
    }

    const { jwt, expiresAt } = await signServiceIdJag({
      registration: result.registration,
      email: result.user.email,
      emailVerified: true,
    });
    res.json({
      registration_id: result.registration.id,
      status: "claimed",
      identity_assertion: jwt,
      assertion_expires: expiresAt.toISOString(),
    });
  },
);

function pickStatusForCompleteError(error: string): number {
  switch (error) {
    case "otp_invalid":
      return 401;
    case "otp_not_generated":
      return 400;
    case "otp_expired":
    case "claim_expired":
      return 410;
    case "previously_claimed":
      return 409;
    default:
      return 400;
  }
}

function humanCompleteError(error: string): string {
  switch (error) {
    case "otp_invalid":
      return "The provided OTP does not match the claim attempt.";
    case "otp_not_generated":
      return "No OTP has been generated for this claim. Open the email link first.";
    case "otp_expired":
      return "The OTP's exchange window has passed.";
    case "claim_expired":
      return "This registration has expired and cannot be claimed.";
    case "previously_claimed":
      return "This registration has already been claimed.";
    default:
      return error;
  }
}

/*
 * User-facing OTP-view page. The email link lands here; the page gates
 * OTP minting behind an explicit user click that POSTs to
 * /agent/identity/claim/attempt/challenge. In production this page is
 * typically gated by a user session to handle edge cases (like updating the
 * email on the claim) upfront instead of in the agent context.
 */
agentAuthRouter.get(`${config.claimEndpointPath}/view`, async (req, res) => {
  const rawToken = req.query.token;
  const token = typeof rawToken === "string" ? rawToken : "";
  if (!token) {
    res
      .status(400)
      .type("html")
      .send(
        renderClaimViewPage({
          ok: false,
          title: "Missing token",
          message: "This link is missing a claim view token.",
        }),
      );
    return;
  }
  const registration = findRegistrationByClaimViewHash(sha256Hex(token));
  if (!registration) {
    res
      .status(404)
      .type("html")
      .send(
        renderClaimViewPage({
          ok: false,
          title: "Link invalid",
          message:
            "This link is no longer valid — it may have been superseded, used, or expired.",
        }),
      );
    return;
  }
  if (registration.status === "claimed") {
    res
      .status(200)
      .type("html")
      .send(
        renderClaimViewPage({
          ok: true,
          title: "Already claimed",
          message:
            "This registration has already been claimed. You can close this tab.",
        }),
      );
    return;
  }
  const attempt = registration.claim?.attempt;
  if (!attempt || attempt.view_expires_at.getTime() < Date.now()) {
    res
      .status(410)
      .type("html")
      .send(
        renderClaimViewPage({
          ok: false,
          title: "Link expired",
          message:
            "This link has expired. Ask the agent to start a new claim to receive a fresh email.",
        }),
      );
    return;
  }
  console.log(
    `[agent-auth] rendered claim-view page for registration=${registration.id}`,
  );
  res
    .status(200)
    .type("html")
    .send(
      renderClaimViewPage({
        ok: true,
        title: "Read this code back to the agent",
        message: `The agent will ask you for a one-time code to confirm you're the owner of <code>${escapeHtml(registration.claim?.email ?? "")}</code>. Read the code below back to the agent — do not share it with anyone else.`,
        claimAttemptToken: token,
      }),
    );
});

function renderClaimViewPage(input: {
  ok: boolean;
  title: string;
  message: string;
  claimAttemptToken?: string;
}): string {
  const headingColor = input.ok ? "var(--brand-primary)" : "var(--error)";
  const challengeUrl = `${config.claimEndpointPath}/attempt/challenge`;
  const otpBlock = input.claimAttemptToken
    ? `
<div class="otp-wrap">
  <div id="otp-out" class="otp-loading">Loading…</div>
  <div id="error-out" class="err" hidden></div>
</div>
<script>
(function () {
  var otpOut = document.getElementById("otp-out");
  var errOut = document.getElementById("error-out");
  var token = ${JSON.stringify(input.claimAttemptToken)};
  fetch(${JSON.stringify(challengeUrl)}, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ claim_attempt_token: token }),
  })
    .then(function (resp) { return resp.json().then(function (data) { return { ok: resp.ok, data: data }; }); })
    .then(function (r) {
      if (!r.ok) {
        otpOut.hidden = true;
        errOut.textContent = r.data.message || r.data.error || "Could not load code.";
        errOut.hidden = false;
        return;
      }
      otpOut.className = "";
      otpOut.textContent = "";
      var otpDiv = document.createElement("div");
      otpDiv.className = "otp";
      otpDiv.textContent = r.data.challenge;
      var metaDiv = document.createElement("div");
      metaDiv.className = "otp-meta";
      metaDiv.textContent = "Expires " + r.data.expires_at;
      otpOut.appendChild(otpDiv);
      otpOut.appendChild(metaDiv);
    })
    .catch(function () {
      otpOut.hidden = true;
      errOut.textContent = "Network error. Try refreshing the page.";
      errOut.hidden = false;
    });
})();
</script>`
    : "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${escapeHtml(input.title)}</title>
<style>
  :root {
    --brand-primary: #6D6DF2;
    --brand-text: #030527;
    --brand-bg: #FFFFFF;
    --error: #e55039;
    --muted: rgba(3, 5, 39, .65);
    --border: rgba(3, 5, 39, .12);
    --surface-soft: rgba(3, 5, 39, .04);
  }
  body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1.5rem; line-height: 1.5; color: var(--brand-text); background: var(--brand-bg); text-align: center; }
  h1 { color: ${headingColor}; }
  p { color: var(--muted); }
  code { background: var(--surface-soft); padding: .05rem .3rem; border-radius: .2rem; font-size: .9em; }
  .otp-wrap { margin: 2rem auto; }
  .otp { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 2.6rem; letter-spacing: .4rem; padding: 1rem 1.5rem; border: 1px solid var(--border); background: var(--surface-soft); border-radius: .5rem; display: inline-block; color: var(--brand-text); }
  .otp-meta { color: var(--muted); font-size: .8rem; margin-top: .5rem; }
  .otp-loading { color: var(--muted); font-size: .9rem; }
  .err { color: var(--error); margin-top: 1rem; font-size: .9rem; }
</style>
</head>
<body>
<h1>${escapeHtml(input.title)}</h1>
<p>${input.message}</p>${otpBlock}
</body></html>`;
}

function escapeHtml(s: string): string {
  return s.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
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
