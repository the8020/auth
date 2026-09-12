import { context } from "@the8020/context";
import { AdminCommandError } from "@the8020/kernel";
import {
  action as actionField,
  failure,
  value as valueField,
} from "../types/auth.ts";
import type { z } from "/p/the8020/db/fields.ts";
import { expression, pattern } from "./matching.ts";

export class AuthorizationError extends AdminCommandError {
  constructor(action: string, value: string) {
    super({
      code: "forbidden",
      message: `Permission denied: ${action} (${value})`,
    });
  }
}

/** Check the current execution user, including inherited roles; audit every denial. */
export async function check(action: string, value: string): Promise<boolean> {
  actionField.parse(action);
  valueField.parse(value);
  const username = context.username;
  if (username === "system") return true;
  const [
    { db },
    { default: Roles },
    { default: UserRoles },
    { default: RoleIncludes },
    { default: Failures },
  ] = await Promise.all([
    import("/p/the8020/db/mod.ts"),
    import("../tables/roles.ts"),
    import("../tables/user_roles.ts"),
    import("../tables/role_includes.ts"),
    import("../tables/failures.ts"),
  ]);
  const details: z.infer<typeof failure>["details"] = [];
  const note = (detail: typeof details[number]) => {
    if (details.length < 100) details.push(detail);
  };
  const reason = await db.transaction().execute(async (tx) => {
    const assignments = await tx.selectFrom(UserRoles.table).select("role")
      .where("username", "=", username).orderBy("role").limit(10001).execute();
    const pending = new Set([username, ...assignments.map((row) => row.role)]);
    const visited = new Set<string>();
    let foundRole = false, foundAction = false;
    while (pending.size) {
      if (visited.size + pending.size > 10000) return "role_limit" as const;
      const batch = Array.from(pending).slice(0, 100);
      for (const name of batch) {
        pending.delete(name);
        visited.add(name);
      }
      const roles = await tx.selectFrom(Roles.table).selectAll().where(
        "name",
        "in",
        batch,
      ).orderBy("name").execute();
      for (const name of batch) {
        if (!roles.some((role) => role.name === name)) {
          note({ role: name, reason: "missing_role" });
        }
      }
      for (const role of roles) {
        foundRole = true;
        let matched = false;
        for (const [key, values] of Object.entries(role.permissions)) {
          try {
            if (!pattern(key)(action)) continue;
            foundAction = matched = true;
            const result = expression(values)(value);
            if (result === "allowed") return undefined;
            note({ role: role.name, action: key, reason: result });
          } catch {
            note({
              role: role.name,
              action: key,
              reason: "invalid_permission",
            });
          }
        }
        if (!matched) note({ role: role.name, reason: "no_action_match" });
      }
      if (roles.length) {
        const links = await tx.selectFrom(RoleIncludes.table).select("included")
          .where("role", "in", roles.map((role) => role.name)).distinct()
          .orderBy("included").limit(10001).execute();
        for (const link of links) {
          if (!visited.has(link.included)) pending.add(link.included);
        }
      }
    }
    return !foundRole
      ? "no_roles" as const
      : !foundAction
      ? "no_action_match" as const
      : "value_not_allowed" as const;
  });
  if (reason === undefined) return true;
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
