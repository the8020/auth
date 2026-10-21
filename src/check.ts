import { context } from "@the8020/context";
import { AdminCommandError } from "@the8020/kernel";
import { action as actionField, value as valueField } from "../types/auth.ts";
import { evaluate, permissionsFor } from "./evaluation.ts";

export class AuthorizationError extends AdminCommandError {
  constructor(action: string, value: string) {
    super({
      code: "forbidden",
      message: `Permission denied: ${action} (${value})`,
    });
  }
}

/**
 * Check the current execution user, including inherited roles. Every denial is
 * audited; a success is audited when `audited(action)` says so.
 */
export async function check(action: string, value: string): Promise<boolean> {
  actionField.parse(action);
  valueField.parse(value);
  const username = context.username;
  if (username === "system") return true;
  const policy = (await permissionsFor(username, [action], true)).get(action)!;
  const { allowed, reason, details, role } = evaluate(policy, value, true);
  if (allowed) {
    const { audited } = await import("./declarations.ts");
    if (await audited(action)) {
      const { default: Grants } = await import("../tables/grants.ts");
      await Grants.insert({
        id: crypto.randomUUID(),
        username,
        action,
        value,
        checkedAt: new Date(),
        role: role ?? "",
      }).execute();
    }
    return true;
  }
  const { default: Failures } = await import("../tables/failures.ts");
  await Failures.insert({
    id: crypto.randomUUID(),
    username,
    action,
    value,
    checkedAt: new Date(),
    reason,
    details,
  }).execute();
  return false;
}

export async function requirePermission(
  action: string,
  value: string,
): Promise<void> {
  if (!await check(action, value)) throw new AuthorizationError(action, value);
}
