import { AdminCommandError } from "@the8020/kernel";
import { type Database, db } from "/p/the8020/db/mod.ts";
import type { Transaction } from "/p/the8020/db/kysely.ts";
import { z } from "/p/the8020/db/fields.ts";
import Users from "/p/the8020/users/tables/users.ts";
import { requirePermission } from "./check.ts";
import {
  assignment,
  inclusion,
  permissions,
  role,
  roleName,
} from "../types/auth.ts";
import Roles from "../tables/roles.ts";
import UserRoles from "../tables/user_roles.ts";
import RoleIncludes from "../tables/role_includes.ts";
import Failures from "../tables/failures.ts";

function missing(kind: string, name: string): never {
  throw new AdminCommandError({
    code: "not_found",
    message: `${kind} ${name} was not found`,
  });
}

async function lockRole(tx: Transaction<Database>, name: string) {
  const result = await tx.updateTable(Roles.table).set({ name }).where(
    "name",
    "=",
    name,
  ).executeTakeFirst();
  return Boolean(result.numUpdatedRows);
}

async function lockUser(tx: Transaction<Database>, username: string) {
  const result = await tx.updateTable(Users.table).set({ username }).where(
    "username",
    "=",
    username,
  ).executeTakeFirst();
  if (!result.numUpdatedRows) missing("User", username);
}

export async function listRoles() {
  await requirePermission("auth.roles.list", "");
  return await Roles.select(["name", "description"]).orderBy("name").limit(1000)
    .execute();
}

export async function getRole(name: string) {
  await requirePermission("auth.roles.view", name);
  return await Roles.selectAll().where("name", "=", name).executeTakeFirst() ??
    missing("Role", name);
}

export async function createRole(
  input: z.infer<typeof role>,
  ifMissing = false,
) {
  const data = role.parse(input);
  await requirePermission("auth.roles.edit", data.name);
  const result = await Roles.insert(data).onConflict((c) =>
    c.column("name").doNothing()
  ).executeTakeFirst();
  if (!result.numInsertedOrUpdatedRows && !ifMissing) {
    throw new AdminCommandError({
      code: "conflict",
      message: `Role ${data.name} already exists`,
    });
  }
  return result.numInsertedOrUpdatedRows
    ? data
    : await Roles.selectAll().where("name", "=", data.name)
      .executeTakeFirstOrThrow();
}

export async function saveRole(input: z.infer<typeof role>) {
  const data = role.parse(input);
  await requirePermission("auth.roles.edit", data.name);
  const result = await Roles.update({
    description: data.description,
    permissions: data.permissions,
  }).where("name", "=", data.name).executeTakeFirst();
  if (!result.numUpdatedRows) missing("Role", data.name);
  return data;
}

export async function setPermission(
  name: string,
  action: string,
  values?: string,
) {
  roleName.parse(name);
  if (values !== undefined) permissions.parse({ [action]: values });
  await requirePermission("auth.roles.edit", name);
  await db.transaction().execute(async (tx) => {
    // Lock this role before editing one entry, preserving concurrent edits.
    if (!await lockRole(tx, name)) missing("Role", name);
    const row = await tx.selectFrom(Roles.table).selectAll().where(
      "name",
      "=",
      name,
    ).executeTakeFirstOrThrow();
    const entries = { ...row.permissions };
    if (values === undefined) delete entries[action];
    else {Object.defineProperty(entries, action, {
        value: values,
        enumerable: true,
        configurable: true,
        writable: true,
      });}
    await tx.updateTable(Roles.table).set({
      permissions: permissions.parse(entries),
    }).where("name", "=", name).execute();
  });
}

export async function deleteRole(name: string) {
  await requirePermission("auth.roles.delete", name);
  await db.transaction().execute(async (tx) => {
    if (!await lockRole(tx, name)) missing("Role", name);
    await tx.deleteFrom(UserRoles.table).where("role", "=", name).execute();
    await tx.deleteFrom(RoleIncludes.table).where((eb) =>
      eb.or([eb("role", "=", name), eb("included", "=", name)])
    ).execute();
    const result = await tx.deleteFrom(Roles.table).where("name", "=", name)
      .executeTakeFirst();
    if (!result.numDeletedRows) missing("Role", name);
  });
}

export async function personalRole(username: string) {
  roleName.parse(username);
  await requirePermission("auth.roles.edit", username);
  await db.transaction().execute(async (tx) => {
    await lockUser(tx, username);
    await tx.insertInto(Roles.table).values({
      name: username,
      description: "",
      permissions: {},
    }).onConflict((c) => c.column("name").doNothing()).execute();
  });
  return username;
}

export async function assignRole(
  username: string,
  name: string,
  assigned = true,
) {
  const data = assignment.parse({ username, role: name });
  await requirePermission("auth.users.edit", username);
  await requirePermission("auth.roles.assign", name);
  await db.transaction().execute(async (tx) => {
    if (!assigned) {
      await tx.deleteFrom(UserRoles.table).where("username", "=", username)
        .where("role", "=", name).execute();
      return;
    }
    // Serialize assignment with account and role deletion.
    await lockUser(tx, username);
    if (!await lockRole(tx, name)) missing("Role", name);
    await tx.insertInto(UserRoles.table).values(data).onConflict((c) =>
      c.columns(["username", "role"]).doNothing()
    ).execute();
  });
}

export async function includeRole(
  name: string,
  included: string,
  enabled = true,
) {
  const data = inclusion.parse({ role: name, included });
  await requirePermission("auth.roles.edit", name);
  await requirePermission("auth.roles.assign", included);
  await db.transaction().execute(async (tx) => {
    if (!enabled) {
      await tx.deleteFrom(RoleIncludes.table).where("role", "=", name).where(
        "included",
        "=",
        included,
      ).execute();
      return;
    }
    for (const target of Array.from(new Set([name, included])).sort()) {
      if (!await lockRole(tx, target)) missing("Role", target);
    }
    await tx.insertInto(RoleIncludes.table).values(data).onConflict((c) =>
      c.columns(["role", "included"]).doNothing()
    ).execute();
  });
}

export async function includedRoles(name: string) {
  await requirePermission("auth.roles.view", name);
  return await RoleIncludes.selectAll().where("role", "=", name).orderBy(
    "included",
  ).limit(1000).execute();
}

export async function userRoles(username: string) {
  await requirePermission("auth.users.view", username);
  const rows = await UserRoles.select(["role"]).where("username", "=", username)
    .orderBy("role").limit(1000).execute();
  const personal = await Roles.select(["name"]).where("name", "=", username)
    .executeTakeFirst();
  const names = new Set(rows.map((row) => row.role));
  if (personal) names.add(username);
  return Array.from(names).sort().map((role) => ({
    role,
    automatic: role === username && personal !== undefined,
    explicit: rows.some((row) => row.role === role),
  }));
}

export async function roleUsers(name: string) {
  await requirePermission("auth.roles.view", name);
  const rows = await UserRoles.select(["username"]).where("role", "=", name)
    .orderBy("username").limit(1000).execute();
  const personal = await Users.select(["username"]).where("username", "=", name)
    .executeTakeFirst();
  const names = new Set(rows.map((row) => row.username));
  if (personal) names.add(name);
  return Array.from(names).sort().map((username) => ({
    username,
    automatic: username === name,
    explicit: rows.some((row) => row.username === username),
  }));
}

/** Auth-owned cleanup for users.deleted; safe to repeat after records are gone. */
export async function removeUserRoles(username: string) {
  await db.transaction().execute(async (tx) => {
    await lockRole(tx, username);
    await tx.deleteFrom(UserRoles.table).where((eb) =>
      eb.or([
        eb("username", "=", username),
        eb("role", "=", username),
      ])
    ).execute();
    await tx.deleteFrom(RoleIncludes.table).where((eb) =>
      eb.or([
        eb("role", "=", username),
        eb("included", "=", username),
      ])
    ).execute();
    await tx.deleteFrom(Roles.table).where("name", "=", username).execute();
  });
}

export async function failedChecks(username?: string, offset = 0) {
  z.number().int().nonnegative().parse(offset);
  await requirePermission("auth.failures.view", username ?? "");
  return await Failures.selectAll().$if(
    username !== undefined,
    (q) => q.where("username", "=", username!),
  ).orderBy("checkedAt", "desc").orderBy("id", "desc").offset(offset).limit(100)
    .execute();
}
