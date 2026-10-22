import { AdminCommandError } from "@the8020/kernel";
import { db } from "/p/the8020/db/mod.ts";
import { z } from "/p/the8020/db/fields.ts";
import Settings from "/p/the8020/system/tables/settings.ts";
import Users from "/p/the8020/users/tables/users.ts";
import Roles from "../tables/roles.ts";
import UserRoles from "../tables/user_roles.ts";
import { roleName } from "../types/auth.ts";
import { requirePermission } from "./check.ts";

/** Roles every new account receives; stored in system settings. */
export const DEFAULT_ROLES_KEY = "auth.default_roles";
export const INITIAL_DEFAULT_ROLES = ["the8020.users.user"];
const MAX_DEFAULT_ROLES = 32;
/** Only accounts this young receive defaults, so a replayed event is inert. */
const NEW_ACCOUNT_MS = 60 * 60_000;
const defaultRoleList = z.array(roleName).max(MAX_DEFAULT_ROLES);

async function storedDefaultRoles(): Promise<string[]> {
  const row = await db.selectFrom(Settings.table).select("value").where(
    "key",
    "=",
    DEFAULT_ROLES_KEY,
  ).executeTakeFirst();
  if (row === undefined) return [...INITIAL_DEFAULT_ROLES];
  const parsed = defaultRoleList.safeParse(row.value);
  return parsed.success ? parsed.data : [];
}

export async function defaultRoles(): Promise<string[]> {
  await requirePermission("the8020.auth.roles.list", "");
  return await storedDefaultRoles();
}

/** Replace the default roles; each must exist. An empty list disables them. */
export async function setDefaultRoles(roles: readonly string[]) {
  await requirePermission("the8020.auth.defaults.edit", "");
  const parsed = defaultRoleList.safeParse([...new Set(roles)]);
  if (!parsed.success) {
    throw new AdminCommandError({
      code: "invalid_arguments",
      message: `at most ${MAX_DEFAULT_ROLES} valid role names are allowed`,
    });
  }
  const names = parsed.data.sort();
  const existing = names.length
    ? new Set(
      (await Roles.select(["name"]).where("name", "in", names).execute()).map((
        row,
      ) => row.name),
    )
    : new Set<string>();
  const missing = names.find((name) => !existing.has(name));
  if (missing !== undefined) {
    throw new AdminCommandError({
      code: "not_found",
      message: `role ${missing} does not exist`,
    });
  }
  const values = {
    value: names,
    definitionHash: "the8020/auth",
    updatedAt: new Date(),
  };
  await db.insertInto(Settings.table).values({
    key: DEFAULT_ROLES_KEY,
    ...values,
  }).onConflict((conflict) => conflict.column("key").doUpdateSet(values))
    .execute();
  return names;
}

/**
 * `users.created` listener: assign the default roles to a just-created
 * account. Missing roles are skipped; existing assignments are kept.
 */
export async function assignDefaultRoles(
  username: string,
  now = new Date(),
): Promise<string[]> {
  const account = await Users.select(["username", "createdAt"]).where(
    "username",
    "=",
    username,
  ).executeTakeFirst();
  if (
    account === undefined ||
    now.getTime() - new Date(account.createdAt).getTime() > NEW_ACCOUNT_MS
  ) return [];
  const wanted = await storedDefaultRoles();
  if (!wanted.length) return [];
  const present = (await Roles.select(["name"]).where("name", "in", wanted)
    .execute()).map((row) => row.name);
  for (const name of wanted) {
    if (!present.includes(name)) {
      console.warn(`Default role ${name} does not exist; not assigned`);
    }
  }
  for (const role of present) {
    await db.insertInto(UserRoles.table).values({
      username,
      role,
      attributes: {},
    }).onConflict((c) => c.columns(["username", "role"]).doNothing())
      .execute();
  }
  return present;
}
