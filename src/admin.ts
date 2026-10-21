import { AdminCommandError } from "@the8020/kernel";
import { type Database, db } from "/p/the8020/db/mod.ts";
import type { Transaction } from "/p/the8020/db/kysely.ts";
import { z } from "/p/the8020/db/fields.ts";
import Users from "/p/the8020/users/tables/users.ts";
import { AuthorizationError, requirePermission } from "./check.ts";
import { context } from "@the8020/context";
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
import {
  isAttributeReference,
  type PermissionValues,
  type RoleEntryValues,
} from "./matching.ts";

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

/** Package-declared roles change only through their declaration. */
async function requireUnmanaged(
  tx: Transaction<Database> | typeof db,
  name: string,
) {
  const row = await tx.selectFrom(Roles.table).select("managed").where(
    "name",
    "=",
    name,
  ).executeTakeFirst();
  if (row?.managed) {
    throw new AdminCommandError({
      code: "conflict",
      message:
        `Role ${name} is managed by ${row.managed}; copy it to make your own version`,
    });
  }
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
  await requirePermission("the8020.auth.roles.list", "");
  return await Roles.select([
    "name",
    "description",
    "managed",
    "collection",
    "obsolete",
  ]).orderBy("name").limit(1000).execute();
}

export async function getRole(name: string) {
  await requirePermission("the8020.auth.roles.view", name);
  return await Roles.selectAll().where("name", "=", name).executeTakeFirst() ??
    missing("Role", name);
}

export async function createRole(
  input: z.infer<typeof role> & { collection?: boolean },
  ifMissing = false,
) {
  const data = role.parse(input);
  await requirePermission("the8020.auth.roles.edit", data.name);
  const result = await Roles.insert({
    ...data,
    collection: input.collection ?? false,
  }).onConflict((c) => c.column("name").doNothing()).executeTakeFirst();
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

export async function saveRole(
  input: z.infer<typeof role> & { collection?: boolean },
) {
  const data = role.parse(input);
  await requirePermission("the8020.auth.roles.edit", data.name);
  await requireUnmanaged(db, data.name);
  const result = await Roles.update({
    ...(input.collection === undefined ? {} : { collection: input.collection }),
    description: data.description,
    permissions: data.permissions,
  }).where("name", "=", data.name).executeTakeFirst();
  if (!result.numUpdatedRows) missing("Role", data.name);
  return data;
}

export async function setPermission(
  name: string,
  action: string,
  values?: RoleEntryValues,
) {
  roleName.parse(name);
  if (values !== undefined) permissions.parse({ [action]: values });
  await requirePermission("the8020.auth.roles.edit", name);
  await db.transaction().execute(async (tx) => {
    // Lock this role before editing one entry, preserving concurrent edits.
    if (!await lockRole(tx, name)) missing("Role", name);
    await requireUnmanaged(tx, name);
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
  await requirePermission("the8020.auth.roles.delete", name);
  await db.transaction().execute(async (tx) => {
    if (!await lockRole(tx, name)) missing("Role", name);
    await requireUnmanaged(tx, name);
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
  await requirePermission("the8020.auth.roles.edit", username);
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

/**
 * Assign or remove a role. Attribute values bind the role's attribute
 * references for this assignment only; omitting them keeps the stored values.
 */
export async function assignRole(
  username: string,
  name: string,
  assigned = true,
  attributes?: Record<string, PermissionValues>,
) {
  const data = assignment.parse({ username, role: name, attributes });
  await requirePermission("the8020.auth.users.edit", username);
  await requirePermission("the8020.auth.roles.assign", name);
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
      attributes === undefined
        ? c.columns(["username", "role"]).doNothing()
        : c.columns(["username", "role"]).doUpdateSet({
          attributes: data.attributes,
        })
    ).execute();
  });
}

export async function includeRole(
  name: string,
  included: string,
  enabled = true,
) {
  const data = inclusion.parse({ role: name, included });
  await requirePermission("the8020.auth.roles.edit", name);
  await requirePermission("the8020.auth.roles.assign", included);
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
    // Managed roles may be included elsewhere but never gain inclusions.
    await requireUnmanaged(tx, name);
    await tx.insertInto(RoleIncludes.table).values(data).onConflict((c) =>
      c.columns(["role", "included"]).doNothing()
    ).execute();
  });
}

/** Attributes referenced by a role and the roles it includes, for assignment. */
export async function roleAttributes(name: string): Promise<string[]> {
  roleName.parse(name);
  await requirePermission("the8020.auth.roles.view", name);
  const attributes = new Set<string>();
  const visited = new Set<string>();
  let pending = [name];
  while (pending.length && visited.size < 1000) {
    for (const role of pending) visited.add(role);
    const rows = await Roles.select(["permissions"]).where(
      "name",
      "in",
      pending,
    )
      .execute();
    for (const row of rows) {
      for (const values of Object.values(row.permissions)) {
        if (isAttributeReference(values)) attributes.add(values.attribute);
      }
    }
    const links = await RoleIncludes.select(["included"]).where(
      "role",
      "in",
      pending,
    ).limit(1000).execute();
    pending = Array.from(new Set(links.map((link) => link.included))).filter(
      (role) => !visited.has(role),
    );
  }
  return Array.from(attributes).sort();
}

export async function includedRoles(name: string) {
  await requirePermission("the8020.auth.roles.view", name);
  return await RoleIncludes.selectAll().where("role", "=", name).orderBy(
    "included",
  ).limit(1000).execute();
}

export async function userRoles(username: string) {
  await requirePermission("the8020.auth.users.view", username);
  return await rolesOf(username);
}

/**
 * The signed-in user's own roles with descriptions and assignment attributes.
 * The trusted identity needs no permission to see its own roles.
 */
export async function ownRoles() {
  if (!context.authenticated) {
    throw new AuthorizationError("the8020.auth.users.view", "");
  }
  const rows = await rolesOf(context.username);
  const described = rows.length
    ? new Map(
      (await Roles.select(["name", "description"]).where(
        "name",
        "in",
        rows.map((row) => row.role),
      ).execute()).map((row) => [row.name, row.description]),
    )
    : new Map<string, string>();
  return rows.map((row) => ({
    ...row,
    description: described.get(row.role) ?? "",
  }));
}

async function rolesOf(username: string) {
  const rows = await UserRoles.select(["role", "attributes"]).where(
    "username",
    "=",
    username,
  ).orderBy("role").limit(1000).execute();
  const personal = await Roles.select(["name"]).where("name", "=", username)
    .executeTakeFirst();
  const names = new Set(rows.map((row) => row.role));
  if (personal) names.add(username);
  return Array.from(names).sort().map((role) => ({
    role,
    automatic: role === username && personal !== undefined,
    explicit: rows.some((row) => row.role === role),
    attributes: rows.find((row) => row.role === role)?.attributes ?? {},
  }));
}

export async function roleUsers(name: string) {
  await requirePermission("the8020.auth.roles.view", name);
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
  await requirePermission("the8020.auth.failures.view", username ?? "");
  return await Failures.selectAll().$if(
    username !== undefined,
    (q) => q.where("username", "=", username!),
  ).orderBy("checkedAt", "desc").orderBy("id", "desc").offset(offset).limit(100)
    .execute();
}

/**
 * Copy a role under a new name. Copying a package-declared role records its
 * origin so the copy can later show and adopt changes of that template.
 */
export async function copyRole(source: string, target: string) {
  roleName.parse(target);
  await requirePermission("the8020.auth.roles.view", source);
  await requirePermission("the8020.auth.roles.edit", target);
  await db.transaction().execute(async (tx) => {
    if (!await lockRole(tx, source)) missing("Role", source);
    const template = await tx.selectFrom(Roles.table).selectAll().where(
      "name",
      "=",
      source,
    ).executeTakeFirstOrThrow();
    const inserted = await tx.insertInto(Roles.table).values({
      name: target,
      description: template.description,
      permissions: template.permissions,
      collection: template.collection,
      managed: null,
      managedCommit: null,
      obsolete: false,
      copiedFrom: template.managed
        ? {
          role: source,
          package: template.managed,
          commit: template.managedCommit ?? "",
        }
        : template.copiedFrom,
    }).onConflict((c) => c.column("name").doNothing()).executeTakeFirst();
    if (!inserted.numInsertedOrUpdatedRows) {
      throw new AdminCommandError({
        code: "conflict",
        message: `Role ${target} already exists`,
      });
    }
    const links = await tx.selectFrom(RoleIncludes.table).select("included")
      .where("role", "=", source).execute();
    for (const { included } of links) {
      await tx.insertInto(RoleIncludes.table).values({ role: target, included })
        .execute();
    }
  });
  return await Roles.selectAll().where("name", "=", target)
    .executeTakeFirstOrThrow();
}

/** One difference between a copy and the current version of its template. */
export interface TemplateChange {
  kind: "permission" | "include";
  key: string;
  change: "added" | "removed" | "changed";
  template?: string;
  copy?: string;
}

/** Differences between a copy and its template's current declaration. */
export async function templateChanges(name: string): Promise<{
  template?: string;
  missing: boolean;
  changes: TemplateChange[];
}> {
  await requirePermission("the8020.auth.roles.view", name);
  const copy = await Roles.selectAll().where("name", "=", name)
    .executeTakeFirst() ?? missing("Role", name);
  if (!copy.copiedFrom) return { missing: false, changes: [] };
  const template = await Roles.selectAll().where(
    "name",
    "=",
    copy.copiedFrom.role,
  ).executeTakeFirst();
  if (!template) {
    return { template: copy.copiedFrom.role, missing: true, changes: [] };
  }
  const text = (value: unknown) => JSON.stringify(value);
  const changes: TemplateChange[] = [];
  for (
    const key of Array.from(
      new Set([
        ...Object.keys(template.permissions),
        ...Object.keys(copy.permissions),
      ]),
    ).sort()
  ) {
    const inTemplate = Object.hasOwn(template.permissions, key);
    const inCopy = Object.hasOwn(copy.permissions, key);
    if (inTemplate && !inCopy) {
      changes.push({
        kind: "permission",
        key,
        change: "added",
        template: text(template.permissions[key]),
      });
    } else if (!inTemplate && inCopy) {
      changes.push({
        kind: "permission",
        key,
        change: "removed",
        copy: text(copy.permissions[key]),
      });
    } else if (
      text(template.permissions[key]) !== text(copy.permissions[key])
    ) {
      changes.push({
        kind: "permission",
        key,
        change: "changed",
        template: text(template.permissions[key]),
        copy: text(copy.permissions[key]),
      });
    }
  }
  const includes = async (role: string) =>
    new Set(
      (await RoleIncludes.select(["included"]).where("role", "=", role)
        .execute()).map((row) => row.included),
    );
  const [templateIncludes, copyIncludes] = await Promise.all([
    includes(template.name),
    includes(name),
  ]);
  for (const key of Array.from(templateIncludes).sort()) {
    if (!copyIncludes.has(key)) {
      changes.push({ kind: "include", key, change: "added" });
    }
  }
  for (const key of Array.from(copyIncludes).sort()) {
    if (!templateIncludes.has(key)) {
      changes.push({ kind: "include", key, change: "removed" });
    }
  }
  return { template: template.name, missing: false, changes };
}

/** Replace a copy's entries and inclusions with its template's current ones. */
export async function adoptTemplate(name: string) {
  await requirePermission("the8020.auth.roles.edit", name);
  await db.transaction().execute(async (tx) => {
    if (!await lockRole(tx, name)) missing("Role", name);
    const copy = await tx.selectFrom(Roles.table).selectAll().where(
      "name",
      "=",
      name,
    ).executeTakeFirstOrThrow();
    if (!copy.copiedFrom) {
      throw new AdminCommandError({
        code: "conflict",
        message: `Role ${name} is not a copy of a package role`,
      });
    }
    const template = await tx.selectFrom(Roles.table).selectAll().where(
      "name",
      "=",
      copy.copiedFrom.role,
    ).executeTakeFirst() ?? missing("Role", copy.copiedFrom.role);
    await tx.updateTable(Roles.table).set({
      description: template.description,
      permissions: template.permissions,
      collection: template.collection,
      copiedFrom: {
        ...copy.copiedFrom,
        commit: template.managedCommit ?? copy.copiedFrom.commit,
      },
    }).where("name", "=", name).execute();
    await tx.deleteFrom(RoleIncludes.table).where("role", "=", name).execute();
    const links = await tx.selectFrom(RoleIncludes.table).select("included")
      .where("role", "=", template.name).execute();
    for (const { included } of links) {
      await tx.insertInto(RoleIncludes.table).values({ role: name, included })
        .execute();
    }
  });
}
