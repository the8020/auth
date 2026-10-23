import { action as actionField, failure, roleName } from "../types/auth.ts";
import type { z } from "/p/the8020/db/fields.ts";
import {
  compileExpression,
  isAttributeReference,
  parseExpression,
  pattern,
  type PermissionTerm,
  type PermissionValues,
} from "./matching.ts";

/** Attribute values carried from the assignment that reached a role. */
type Binding = Record<string, PermissionValues>;
interface Reached {
  name: string;
  binding: Binding;
}

/** Roles reached through different assignments are distinct traversal items. */
function reachedKey({ name, binding }: Reached): string {
  return `${name}\u0000${
    JSON.stringify(
      Object.keys(binding).sort().map((key) => [key, binding[key]]),
    )
  }`;
}

type Detail = z.infer<typeof failure>["details"][number];
type Reason = z.infer<typeof failure>["reason"];
type Entry = Detail & {
  terms?: PermissionTerm[];
  match?: ReturnType<typeof compileExpression>;
};
export interface Policy {
  bypass: boolean;
  reason: Reason;
  entries: Entry[];
}

/** One bounded role traversal per invocation, independent of row/property count. */
export async function permissionsFor(
  username: string,
  actions: string[],
  trustedPrincipal = false,
): Promise<Map<string, Policy>> {
  roleName.parse(username);
  const policies = new Map<string, Policy>();
  for (const action of actions) {
    actionField.parse(action);
    policies.set(action, {
      bypass: username === "system",
      reason: "no_roles",
      entries: [],
    });
  }
  if (username === "system" || policies.size === 0) return policies;
  const [
    { db },
    { default: Roles },
    { default: UserRoles },
    { default: RoleIncludes },
    { default: Users },
  ] = await Promise.all([
    import("/p/the8020/db/mod.ts"),
    import("../tables/roles.ts"),
    import("../tables/user_roles.ts"),
    import("../tables/role_includes.ts"),
    import("/p/the8020/users/tables/users.ts"),
  ]);
  await db.transaction().execute(async (tx) => {
    // Trusted service principals need not have a users-package account.
    if (!trustedPrincipal) {
      const account = await tx.selectFrom(Users.table).select("username")
        .where("username", "=", username).executeTakeFirst();
      if (!account) return;
    }
    const assignments = await tx.selectFrom(UserRoles.table).select([
      "role",
      "attributes",
    ]).where("username", "=", username).orderBy("role").limit(10001)
      .execute();
    // The personal role has no assignment and therefore binds no attributes.
    const pending = new Map<string, Reached>();
    for (
      const reached of [
        { name: username, binding: {} },
        ...assignments.map((row) => ({
          name: row.role,
          binding: row.attributes ?? {},
        })),
      ]
    ) pending.set(reachedKey(reached), reached);
    const visited = new Set<string>();
    while (pending.size) {
      if (visited.size + pending.size > 10000) {
        for (const policy of policies.values()) policy.reason = "role_limit";
        return;
      }
      const batch = Array.from(pending).slice(0, 100);
      for (const [key] of batch) {
        pending.delete(key);
        visited.add(key);
      }
      const names = Array.from(new Set(batch.map(([, item]) => item.name)));
      const roles = new Map(
        (await tx.selectFrom(Roles.table).selectAll().where("name", "in", names)
          .orderBy("name").execute()).map((role) => [role.name, role]),
      );
      for (const name of names) {
        if (!roles.has(name)) {
          for (const policy of policies.values()) {
            policy.entries.push({ role: name, reason: "missing_role" });
          }
        }
      }
      for (const [, { name, binding }] of batch) {
        const role = roles.get(name);
        if (role === undefined) continue;
        const matched = new Set<string>();
        for (const [key, stored] of Object.entries(role.permissions)) {
          let matches: (value: string) => boolean;
          try {
            matches = pattern(key);
          } catch {
            for (const policy of policies.values()) {
              policy.entries.push({
                role: role.name,
                action: key,
                reason: "invalid_permission",
              });
            }
            continue;
          }
          const targets = [...policies.keys()].filter(matches);
          if (!targets.length) continue;
          // An attribute reference takes its values from the binding; an
          // unbound attribute grants nothing.
          const values = isAttributeReference(stored)
            ? binding[stored.attribute]
            : stored;
          let terms: PermissionTerm[] | undefined, match: Entry["match"];
          if (values !== undefined) {
            try {
              terms = parseExpression(values);
              match = compileExpression(terms);
            } catch { /* Invalid stored entries never grant. */ }
          }
          for (const action of targets) {
            matched.add(action);
            const policy = policies.get(action)!;
            policy.reason = "value_not_allowed";
            policy.entries.push({
              role: role.name,
              action: key,
              reason: values === undefined
                ? "unbound_attribute"
                : "invalid_permission",
              terms,
              match,
            });
          }
        }
        for (const [action, policy] of policies) {
          if (policy.reason === "no_roles") policy.reason = "no_action_match";
          if (!matched.has(action)) {
            policy.entries.push({ role: role.name, reason: "no_action_match" });
          }
        }
      }
      if (roles.size) {
        const links = await tx.selectFrom(RoleIncludes.table).select([
          "role",
          "included",
        ]).where("role", "in", Array.from(roles.keys())).orderBy("role")
          .orderBy("included").limit(10001).execute();
        // Included roles inherit the binding of the path that reached them.
        for (const [, { name, binding }] of batch) {
          for (const link of links) {
            if (link.role !== name) continue;
            const reached = { name: link.included, binding };
            const key = reachedKey(reached);
            if (!visited.has(key)) pending.set(key, reached);
          }
        }
      }
    }
  });
  return policies;
}

export function evaluate(policy: Policy, value: string, diagnostics = false) {
  const details: Detail[] = [];
  if (policy.bypass) return { allowed: true, reason: policy.reason, details };
  if (policy.reason === "role_limit") {
    return { allowed: false, reason: policy.reason, details };
  }
  for (const entry of policy.entries) {
    const reason = entry.match?.(value) ?? entry.reason;
    if (reason === "allowed") {
      return {
        allowed: true,
        reason: policy.reason,
        details,
        role: entry.role,
      };
    }
    if (diagnostics && details.length < 100) {
      details.push({
        role: entry.role,
        ...(entry.action === undefined ? {} : { action: entry.action }),
        reason,
      });
    }
  }
  return { allowed: false, reason: policy.reason, details };
}
