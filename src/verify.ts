import { value as valueField } from "../types/auth.ts";
import { evaluate, permissionsFor } from "./evaluation.ts";

/** Read-only permission query for an explicit username (not a user:<name> ID). */
export async function verify(
  username: string,
  action: string,
  value: string,
): Promise<boolean> {
  valueField.parse(value);
  return evaluate(
    (await permissionsFor(username, [action])).get(action)!,
    value,
  ).allowed;
}

/** Each own property maps to one scalar action; all mapped checks must pass. */
export async function filter<T extends object>(
  username: string,
  rows: readonly T[],
  mapping: Partial<Record<keyof T, string>>,
): Promise<T[]> {
  const fields = (Reflect.ownKeys(mapping) as (keyof T)[]).map((property) => ({
    property,
    action: mapping[property]!,
  }));
  if (!fields.length) {
    throw new TypeError("At least one property/action mapping is required");
  }
  const policies = await permissionsFor(
    username,
    fields.map(({ action }) => action),
  );
  return rows.filter((row) =>
    fields.every(({ property, action }) => {
      if (
        row === null || typeof row !== "object" || !Object.hasOwn(row, property)
      ) return false;
      const value = row[property];
      return typeof value === "string" && value.length <= 2048 &&
        evaluate(policies.get(action)!, value).allowed;
    })
  );
}

/**
 * Whether any reachable role entry can grant the action for some value, for
 * menus and tiles. Like `verify`, it never audits. Enforcement still checks
 * the actual value.
 */
export async function permitsAny(
  username: string,
  action: string,
): Promise<boolean> {
  const policy = (await permissionsFor(username, [action])).get(action)!;
  if (policy.bypass) return true;
  if (policy.reason === "role_limit") return false;
  return policy.entries.some((entry) =>
    entry.terms?.some((term) => !term.excluded) ?? false
  );
}

/** Upper bound on accounts one `usersWithPermission` call evaluates. */
const MAX_USERS = 10_000;

/**
 * Enabled accounts whose roles grant the action for the value, sorted, for
 * notifications and assignment pickers. Like `verify`, it never audits and
 * never consults the caller's own permissions; `system` is not an account.
 */
export async function usersWithPermission(
  action: string,
  value: string,
): Promise<string[]> {
  valueField.parse(value);
  const [{ db }, { default: Users }] = await Promise.all([
    import("/p/the8020/db/mod.ts"),
    import("/p/the8020/users/tables/users.ts"),
  ]);
  const accounts = await db.selectFrom(Users.table).select("username").where(
    "enabled",
    "=",
    true,
  ).orderBy("username").limit(MAX_USERS + 1).execute();
  if (accounts.length > MAX_USERS) {
    throw new RangeError(`More than ${MAX_USERS} accounts to evaluate`);
  }
  const granted: string[] = [];
  // A few accounts at a time keeps the role traversals bounded.
  for (let offset = 0; offset < accounts.length; offset += 8) {
    const batch = accounts.slice(offset, offset + 8);
    const results = await Promise.all(
      batch.map(({ username }) => verify(username, action, value)),
    );
    batch.forEach(({ username }, index) => {
      if (results[index]) granted.push(username);
    });
  }
  return granted;
}
