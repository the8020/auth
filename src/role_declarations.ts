import { parse } from "/p/the8020/packages/toml.ts";
import { db } from "/p/the8020/db/mod.ts";
import { z } from "/p/the8020/db/fields.ts";
import { permissions, role, roleName } from "../types/auth.ts";
import Roles from "../tables/roles.ts";
import RoleIncludes from "../tables/role_includes.ts";
import UserRoles from "../tables/user_roles.ts";
import AuditFlags from "../tables/audit_flags.ts";
import { parseActionDeclarations, resetAuditCache } from "./declarations.ts";

/** One role a package declares in `declarations/auth-roles.toml`. */
export interface DeclaredRole {
  name: string;
  description: string;
  permissions: z.infer<typeof permissions>;
  collection: boolean;
  includes: string[];
}

/** Scope handed to `index-packages` handlers. */
export interface IndexScope {
  packages: { package_id: string; package_commit: string; active: boolean }[];
}
export interface IndexState {
  packages: Record<string, { error?: string }>;
}

const MAX_FILE_BYTES = 1 << 20;
const MAX_ROLES = 256;
const MAX_INCLUDES = 64;

/** The role and action prefix of a package: `the8020/users` → `the8020.users.`. */
export function packagePrefix(packageId: string): string {
  return `${packageId.replace("/", ".")}.`;
}

export function parseRoleDeclarations(
  text: string,
  packageId: string,
): DeclaredRole[] {
  const source = parse(text) as Record<string, unknown>;
  const prefix = packagePrefix(packageId);
  const entries = Object.entries(source);
  if (entries.length > MAX_ROLES) {
    throw new TypeError(`A package declares at most ${MAX_ROLES} roles`);
  }
  return entries.map(([name, value]) => {
    roleName.parse(name);
    if (!name.startsWith(prefix) || name.length === prefix.length) {
      throw new TypeError(`Role ${name} must start with ${prefix}`);
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new TypeError(`Role ${name} must be a table`);
    }
    const entry = value as Record<string, unknown>;
    const unknown = Object.keys(entry).find((key) =>
      !["description", "permissions", "collection", "includes"].includes(key)
    );
    if (unknown !== undefined) {
      throw new TypeError(`Role ${name} has unknown key ${unknown}`);
    }
    const includes = entry.includes ?? [];
    if (
      !Array.isArray(includes) || includes.length > MAX_INCLUDES ||
      !includes.every((item) => typeof item === "string")
    ) {
      throw new TypeError(
        `Role ${name} includes must be at most ${MAX_INCLUDES} role names`,
      );
    }
    if (
      entry.collection !== undefined && typeof entry.collection !== "boolean"
    ) {
      throw new TypeError(`Role ${name} collection must be true or false`);
    }
    return {
      name,
      description: role.shape.description.parse(entry.description ?? ""),
      permissions: permissions.parse(entry.permissions ?? {}),
      collection: entry.collection === true,
      includes: (includes as string[]).map((item) => roleName.parse(item)),
    };
  });
}

/** A package's declaration file text, or undefined when it has none. */
async function readDeclarationFile(
  packageId: string,
  name: string,
  root: URL,
): Promise<string | undefined> {
  const file = new URL(`${packageId}/declarations/${name}`, root);
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(file);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return undefined;
    throw error;
  }
  if (!info.isFile) throw new TypeError(`${name} must be a file`);
  if (info.size > MAX_FILE_BYTES) throw new TypeError(`${name} exceeds 1 MiB`);
  return await Deno.readTextFile(file);
}

async function readDeclarations(
  packageId: string,
  root: URL,
): Promise<DeclaredRole[]> {
  const text = await readDeclarationFile(packageId, "auth-roles.toml", root);
  return text === undefined ? [] : parseRoleDeclarations(text, packageId);
}

/**
 * Declared `audit` flags of the package's own actions. A package cannot change
 * how another package's actions are audited.
 */
export async function readAuditFlags(
  packageId: string,
  root: URL,
  problems: string[],
): Promise<Map<string, boolean>> {
  const text = await readDeclarationFile(packageId, "auth.toml", root);
  const flags = new Map<string, boolean>();
  if (text === undefined) return flags;
  const prefix = packagePrefix(packageId);
  for (const item of parseActionDeclarations(text)) {
    if (item.audit === undefined) continue;
    if (!item.action.startsWith(prefix)) {
      problems.push(`audit of ${item.action} must be declared by its package`);
      continue;
    }
    flags.set(item.action, item.audit);
  }
  return flags;
}

export async function synchronizeAuditFlags(
  packageId: string,
  flags: ReadonlyMap<string, boolean>,
): Promise<void> {
  await db.transaction().execute(async (tx) => {
    await tx.deleteFrom(AuditFlags.table).where("packageId", "=", packageId)
      .execute();
    for (const [action, audit] of flags) {
      await tx.insertInto(AuditFlags.table).values({ action, packageId, audit })
        .onConflict((c) => c.column("action").doUpdateSet({ packageId, audit }))
        .execute();
    }
  });
  resetAuditCache();
}

/**
 * `index-packages` handler: make each selected package's managed roles and
 * declared audit flags match its declarations. A role created by hand or by another package is never
 * taken over. Removed roles still in use become obsolete; unused ones go.
 */
export async function indexRoles(
  state: IndexState,
  scope: Readonly<IndexScope>,
  root = new URL("file:///workspace/packages/"),
): Promise<void> {
  for (const selected of scope.packages) {
    const problems: string[] = [];
    try {
      const declared = selected.active
        ? await readDeclarations(selected.package_id, root)
        : [];
      await synchronize(
        selected.package_id,
        selected.package_commit,
        declared,
        problems,
      );
    } catch (error) {
      problems.push(error instanceof Error ? error.message : String(error));
    }
    try {
      await synchronizeAuditFlags(
        selected.package_id,
        selected.active
          ? await readAuditFlags(selected.package_id, root, problems)
          : new Map(),
      );
    } catch (error) {
      problems.push(error instanceof Error ? error.message : String(error));
    }
    if (problems.length) {
      state.packages[selected.package_id] ??= {};
      state.packages[selected.package_id]!.error = problems.join("; ");
    }
  }
}

export async function synchronize(
  packageId: string,
  commit: string,
  declared: readonly DeclaredRole[],
  problems: string[],
): Promise<void> {
  await db.transaction().execute(async (tx) => {
    const names = declared.map((item) => item.name);
    const current = names.length
      ? await tx.selectFrom(Roles.table).select(["name", "managed"]).where(
        "name",
        "in",
        names,
      ).execute()
      : [];
    const owners = new Map(current.map((row) => [row.name, row.managed]));
    const applied: DeclaredRole[] = [];
    for (const item of declared) {
      if (owners.has(item.name) && owners.get(item.name) !== packageId) {
        problems.push(
          `Role ${item.name} already exists and is not managed by ${packageId}`,
        );
        continue;
      }
      const values = {
        description: item.description,
        permissions: item.permissions,
        collection: item.collection,
        managed: packageId,
        managedCommit: commit,
        obsolete: false,
        copiedFrom: null,
      };
      await tx.insertInto(Roles.table).values({ name: item.name, ...values })
        .onConflict((c) => c.column("name").doUpdateSet(values)).execute();
      applied.push(item);
    }
    // Inclusions follow the declaration once every declared role exists.
    for (const item of applied) {
      await tx.deleteFrom(RoleIncludes.table).where("role", "=", item.name)
        .execute();
      for (const included of item.includes) {
        const exists = await tx.selectFrom(Roles.table).select("name").where(
          "name",
          "=",
          included,
        ).executeTakeFirst();
        if (!exists) {
          problems.push(`Role ${item.name} includes missing role ${included}`);
          continue;
        }
        await tx.insertInto(RoleIncludes.table).values({
          role: item.name,
          included,
        }).onConflict((c) => c.columns(["role", "included"]).doNothing())
          .execute();
      }
    }
    const removed = await tx.selectFrom(Roles.table).select("name").where(
      "managed",
      "=",
      packageId,
    ).execute();
    for (const { name } of removed) {
      if (names.includes(name)) continue;
      const used = await tx.selectFrom(UserRoles.table).select("role").where(
        "role",
        "=",
        name,
      ).executeTakeFirst() ??
        await tx.selectFrom(RoleIncludes.table).select("role").where(
          "included",
          "=",
          name,
        ).executeTakeFirst();
      if (used) {
        await tx.updateTable(Roles.table).set({ obsolete: true }).where(
          "name",
          "=",
          name,
        ).execute();
      } else {
        await tx.deleteFrom(RoleIncludes.table).where("role", "=", name)
          .execute();
        await tx.deleteFrom(Roles.table).where("name", "=", name).execute();
      }
    }
  });
}
