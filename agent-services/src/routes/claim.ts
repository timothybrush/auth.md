import type { Request, Response } from "express";
import { Router } from "express";
import { config } from "../config.js";
import { claimFormBody, parseBody } from "../schemas.js";
import {
  type Registration,
  type User,
  completeClaim,
  findRegistrationByClaimViewHash,
  findSession,
  sha256Hex,
  users,
} from "../store.js";

/*
 * User-facing claim form. Cookie-gated by /login. The agent never reaches
 * this code — it polls /oauth2/token with
 * grant_type=urn:workos:agent-auth:grant-type:claim for the resulting status.
 *
 * The query parameter `claim_attempt_token` (an extension to RFC 8628's
 * verification URL) identifies which registration this page is for, without
 * leaking the user-typed `user_code` into link previews or browser history.
 */

export const claimRouter = Router();

claimRouter.get("/claim", (req, res) => {
  const token =
    typeof req.query.claim_attempt_token === "string"
      ? req.query.claim_attempt_token
      : "";
  const user = requireUser(req, res, returnToFor(token));
  if (!user) return;

  const registration = lookupRegistration(token);
  if (!registration) {
    res
      .status(404)
      .type("html")
      .send(
        renderClaimPage({
          status: "error",
          title: "Link invalid",
          message:
            "This claim link is no longer valid — it may have been superseded, used, or expired. Ask the agent to start a new claim.",
        }),
      );
    return;
  }
  if (registration.status === "claimed") {
    res
      .status(200)
      .type("html")
      .send(
        renderClaimPage({
          status: "done",
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
        renderClaimPage({
          status: "error",
          title: "Link expired",
          message:
            "This claim link has expired. Ask the agent to start a new claim.",
        }),
      );
    return;
  }

  /*
   * Agent asserted a specific email — only that signed-in user can complete.
   * Applies to both email_verification (email is the agent's identity claim)
   * and anonymous (email binds the registration to the human the agent
   * surfaced the user_code to, preventing third-party claim hijacks).
   */
  const wrongAccount = wrongAccountError(registration, user);
  if (wrongAccount) {
    res.status(403).type("html").send(wrongAccount);
    return;
  }

  res.type("html").send(
    renderClaimPage({
      status: "form",
      title: "Confirm the code from your agent",
      message: `You're signed in as <code>${escapeHtml(user.email)}</code>. The agent should have shown you a 6-digit code — enter it below to authorize it to act on your behalf.`,
      claimAttemptToken: token,
    }),
  );
});

/*
 * Form-action endpoint. Same path the agent used to call in the old flow,
 * but the body and auth context are different: cookie-gated, with the user
 * supplying the user_code they got from the agent.
 */
claimRouter.post(`${config.claimEndpointPath}/complete`, (req, res) => {
  const parsed = parseBody(claimFormBody, req.body);
  if (!parsed.ok) {
    res
      .status(400)
      .type("html")
      .send(
        renderClaimPage({
          status: "error",
          title: "Invalid submission",
          message: parsed.message,
        }),
      );
    return;
  }

  const user = requireUser(
    req,
    res,
    returnToFor(parsed.value.claim_attempt_token),
  );
  if (!user) return;

  const registration = lookupRegistration(parsed.value.claim_attempt_token);
  if (!registration) {
    res
      .status(404)
      .type("html")
      .send(
        renderClaimPage({
          status: "error",
          title: "Link invalid",
          message:
            "This claim link is no longer valid. Ask the agent to start a new claim.",
        }),
      );
    return;
  }

  const wrongAccount = wrongAccountError(registration, user);
  if (wrongAccount) {
    res.status(403).type("html").send(wrongAccount);
    return;
  }

  const result = completeClaim(registration, parsed.value.user_code, user);
  if (!result.ok) {
    res
      .status(statusForError(result.error))
      .type("html")
      .send(
        renderClaimPage({
          status: "form-error",
          title: "Confirm the code from your agent",
          message: `You're signed in as <code>${escapeHtml(user.email)}</code>. Enter the 6-digit code your agent gave you.`,
          claimAttemptToken: parsed.value.claim_attempt_token,
          error: humanError(result.error),
        }),
      );
    return;
  }

  console.log(
    `[claim] registration=${result.registration.id} claimed by user=${user.id}`,
  );

  res
    .status(200)
    .type("html")
    .send(
      renderClaimPage({
        status: "done",
        title: "All set",
        message:
          "The agent has been authorized to act on your behalf. You can close this tab — the agent will pick up automatically.",
      }),
    );
});

function requireUser(
  req: Request,
  res: Response,
  returnTo: string,
): User | undefined {
  const token = req.cookies?.[config.sessionCookieName] ?? "";
  const session = token ? findSession(token) : undefined;
  if (!session) {
    res.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`);
    return undefined;
  }
  const user = users.get(session.user_id);
  if (!user) {
    res.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`);
    return undefined;
  }
  return user;
}

function lookupRegistration(token: string): Registration | undefined {
  if (!token) return undefined;
  return findRegistrationByClaimViewHash(sha256Hex(token));
}

function returnToFor(token: string): string {
  return `/claim?claim_attempt_token=${encodeURIComponent(token)}`;
}

function wrongAccountError(
  registration: Registration,
  user: User,
): string | undefined {
  const claimEmail = registration.claim?.email;
  if (!claimEmail) return undefined;
  if (claimEmail.toLowerCase() === user.email.toLowerCase()) return undefined;
  return renderClaimPage({
    status: "error",
    title: "Wrong account",
    message: `This claim was started for <code>${escapeHtml(claimEmail)}</code>. You're signed in as <code>${escapeHtml(user.email)}</code>. Sign out and sign back in with the right account.`,
  });
}

function statusForError(error: string): number {
  switch (error) {
    case "user_code_invalid":
      return 401;
    case "user_code_expired":
    case "claim_expired":
      return 410;
    case "previously_claimed":
      return 409;
    default:
      return 400;
  }
}

function humanError(error: string): string {
  switch (error) {
    case "user_code_invalid":
      return "That code doesn't match. Check the digits and try again.";
    case "user_code_expired":
      return "That code has expired. Ask the agent for a fresh code.";
    case "claim_expired":
      return "This claim has expired. Ask the agent to start a new one.";
    case "previously_claimed":
      return "This registration has already been claimed.";
    default:
      return error;
  }
}

function renderClaimPage(input: {
  status: "form" | "form-error" | "done" | "error";
  title: string;
  message: string;
  claimAttemptToken?: string;
  error?: string;
}): string {
  const isError = input.status === "error";
  const headingColor = isError ? "var(--error)" : "var(--brand-primary)";

  const formBlock =
    input.status === "form" || input.status === "form-error"
      ? `
<form method="POST" action="${config.claimEndpointPath}/complete">
  <input type="hidden" name="claim_attempt_token" value="${escapeAttr(input.claimAttemptToken ?? "")}">
  <label>
    6-digit code
    <input
      type="text"
      name="user_code"
      inputmode="numeric"
      pattern="[0-9]{6}"
      maxlength="6"
      autocomplete="one-time-code"
      placeholder="000000"
      required
      autofocus
    >
  </label>
  ${input.error ? `<p class="err">${escapeHtml(input.error)}</p>` : ""}
  <button type="submit">Authorize agent</button>
</form>
<p class="warn">Only enter a code from an agent you trust. Pasting a code from an untrusted source could let that agent act on your behalf.</p>
`
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
    --warn-bg: rgba(245, 158, 11, .08);
    --warn-border: rgba(245, 158, 11, .35);
    --warn-text: #8a5a00;
  }
  body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1.5rem; line-height: 1.5; color: var(--brand-text); background: var(--brand-bg); }
  h1 { color: ${headingColor}; }
  p { color: var(--muted); }
  code { background: var(--surface-soft); padding: .05rem .3rem; border-radius: .2rem; font-size: .9em; }
  form { margin-top: 1.5rem; display: flex; flex-direction: column; gap: .75rem; }
  label { font-size: .85rem; font-weight: 600; color: var(--brand-text); }
  input { width: 100%; padding: .65rem .75rem; border: 1px solid var(--border); border-radius: .35rem; font-size: 1.4rem; letter-spacing: .35rem; font-family: ui-monospace, "SF Mono", Menlo, monospace; text-align: center; background: var(--brand-bg); color: var(--brand-text); }
  button { padding: .7rem 1rem; background: var(--brand-primary); color: white; border: none; border-radius: .35rem; font-weight: 600; font-size: 1rem; cursor: pointer; }
  button:hover { filter: brightness(1.08); }
  .err { color: var(--error); background: rgba(229, 80, 57, .08); border: 1px solid rgba(229, 80, 57, .35); padding: .5rem .75rem; border-radius: .35rem; font-size: .85rem; margin: 0; }
  .warn { background: var(--warn-bg); border: 1px solid var(--warn-border); color: var(--warn-text); padding: .6rem .8rem; border-radius: .35rem; font-size: .8rem; margin-top: 1rem; }
</style>
</head>
<body>
<h1>${escapeHtml(input.title)}</h1>
<p>${input.message}</p>
${formBlock}
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

function escapeAttr(s: string): string {
  return escapeHtml(s);
}
