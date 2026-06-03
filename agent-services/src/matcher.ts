import type { IdJagClaims } from "./verify.js";
import {
  type User,
  createUser,
  findDelegation,
  findUserByEmail,
  findUserByPhone,
  upsertDelegation,
  users,
} from "./store.js";

/**
 * Result of resolving an ID-JAG against the service's user store.
 *
 * - `match` — either an existing (iss, sub) delegation, or a JIT-provisioned
 *   user for an ID-JAG whose claims didn't match anyone. Safe to bind
 *   credentials to immediately.
 * - `step_up_required` — the ID-JAG's email or phone matched an existing
 *   account but no (iss, sub) delegation is on file yet. The service won't
 *   bind silently; the user must confirm linking the provider identity to
 *   their account via the claim ceremony.
 */
export type MatchResult =
  | { kind: "match"; user: User; match: "delegation" | "jit" }
  | { kind: "step_up_required"; via: "email" | "phone"; matched_user: User };

export function matchOrProvision(claims: IdJagClaims): MatchResult {
  const { iss, sub } = claims;

  const existingDelegation = findDelegation(iss, sub);
  if (existingDelegation) {
    const user = users.get(existingDelegation.user_id);
    if (user) {
      upsertDelegation(iss, sub, user.id);
      return { kind: "match", user, match: "delegation" };
    }
  }

  /*
   * Email- or phone-match against an existing account requires the user to
   * prove ownership before we bind a new (iss, sub) delegation. Without
   * this gate any trusted provider could mint an ID-JAG with
   * email_verified/phone_number_verified set for a victim's identifier and
   * silently take over the victim's account at this service.
   */
  if (claims.email && claims.email_verified) {
    const byEmail = findUserByEmail(claims.email);
    if (byEmail) {
      return { kind: "step_up_required", via: "email", matched_user: byEmail };
    }
  }

  if (claims.phone_number && claims.phone_number_verified) {
    const byPhone = findUserByPhone(claims.phone_number);
    if (byPhone) {
      return { kind: "step_up_required", via: "phone", matched_user: byPhone };
    }
  }

  const user = createUser({
    email: claims.email ?? `agent+${sub}@jit.local`,
    email_verified: Boolean(claims.email_verified),
    phone_number: claims.phone_number,
    phone_number_verified: claims.phone_number_verified,
    name: claims.name,
  });
  upsertDelegation(iss, sub, user.id);
  return { kind: "match", user, match: "jit" };
}
