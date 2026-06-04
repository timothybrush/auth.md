import { Router } from "express";
import { config } from "../config.js";
import { loginFormBody, parseBody } from "../schemas.js";
import {
  createSession,
  createUser,
  destroySession,
  findSession,
  findUserByEmail,
  users,
} from "../store.js";

/*
 * Mock IdP. In production this would be a real authentication system
 * (AuthKit, your homegrown sign-in, etc.). We need just enough here to issue
 * a cookie-bound session so the /claim form can identify the signed-in user.
 */

export const loginRouter = Router();

loginRouter.get("/login", (req, res) => {
  const returnTo = sanitizeReturnTo(req.query.return_to);
  const cookieToken = readSessionCookie(req);
  if (cookieToken && findSession(cookieToken)) {
    res.redirect(returnTo);
    return;
  }
  res.type("html").send(renderLoginPage({ returnTo }));
});

loginRouter.post("/login", (req, res) => {
  const parsed = parseBody(loginFormBody, req.body);
  if (!parsed.ok) {
    res
      .status(400)
      .type("html")
      .send(renderLoginPage({ returnTo: "/", error: parsed.message }));
    return;
  }
  const email = parsed.value.email.toLowerCase();
  const returnTo = sanitizeReturnTo(parsed.value.return_to);

  let user = findUserByEmail(email);
  if (!user) {
    /*
     * Auto-provision unknown emails so demo testers don't have to seed
     * users. A real IdP would route to a sign-up flow with email
     * verification here.
     */
    user = createUser({ email, email_verified: true });
  }

  const session = createSession(user.id);
  res.cookie(config.sessionCookieName, session.token, {
    httpOnly: true,
    secure: process.env.NODE_ENV !== "development",
    sameSite: "lax",
    path: "/",
    maxAge: config.sessionTtlSeconds * 1000,
  });
  console.log(`[login] signed in user=${user.id} email=${user.email}`);
  res.redirect(returnTo);
});

loginRouter.post("/logout", (req, res) => {
  const token = readSessionCookie(req);
  if (token) destroySession(token);
  res.clearCookie(config.sessionCookieName, { path: "/" });
  res.redirect("/login");
});

function readSessionCookie(req: { cookies?: Record<string, string> }): string {
  return req.cookies?.[config.sessionCookieName] ?? "";
}

/** Same-origin paths only. Anything else falls back to "/". */
function sanitizeReturnTo(raw: unknown): string {
  if (typeof raw !== "string" || raw.length === 0) return "/";
  if (!raw.startsWith("/") || raw.startsWith("//")) return "/";
  return raw;
}

function renderLoginPage(input: { returnTo: string; error?: string }): string {
  const seededOptions = Array.from(users.values())
    .filter((u) => u.email_verified)
    .map(
      (u) =>
        `<option value="${escapeAttr(u.email)}">${escapeHtml(u.email)}</option>`,
    )
    .join("");
  const errorBlock = input.error
    ? `<p class="err">${escapeHtml(input.error)}</p>`
    : "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in</title>
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
  body { font-family: system-ui, sans-serif; max-width: 28rem; margin: 4rem auto; padding: 0 1.5rem; line-height: 1.5; color: var(--brand-text); background: var(--brand-bg); }
  h1 { margin-bottom: .25rem; }
  p { color: var(--muted); }
  form { margin-top: 1.5rem; display: flex; flex-direction: column; gap: .75rem; }
  label { font-size: .85rem; font-weight: 600; }
  input, select { width: 100%; padding: .55rem .65rem; border: 1px solid var(--border); border-radius: .35rem; font-size: 1rem; background: var(--brand-bg); color: var(--brand-text); }
  button { padding: .65rem 1rem; background: var(--brand-primary); color: white; border: none; border-radius: .35rem; font-weight: 600; font-size: 1rem; cursor: pointer; }
  button:hover { filter: brightness(1.08); }
  .err { color: var(--error); background: rgba(229, 80, 57, .08); border: 1px solid rgba(229, 80, 57, .35); padding: .5rem .75rem; border-radius: .35rem; font-size: .85rem; }
  .seed { margin-top: .5rem; font-size: .8rem; color: var(--muted); }
  .seed code { background: var(--surface-soft); padding: .05rem .3rem; border-radius: .2rem; }
</style>
</head>
<body>
<h1>Sign in</h1>
<p>Mock identity provider. Any email works — unknown emails are auto-provisioned for the demo.</p>
${errorBlock}
<form method="POST" action="/login">
  <input type="hidden" name="return_to" value="${escapeAttr(input.returnTo)}">
  <label>
    Email
    <input type="email" name="email" placeholder="you@example.com" required autofocus list="seeded-users">
  </label>
  <datalist id="seeded-users">${seededOptions}</datalist>
  <button type="submit">Continue</button>
</form>
<p class="seed">Seeded: <code>alice@service.example.com</code>, <code>bob@service.example.com</code></p>
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
