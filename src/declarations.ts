import { parse } from "/p/the8020/packages/toml.ts";
import { action, attributeName, role } from "../types/auth.ts";

/** Advisory declarations never constrain the keys accepted by authorization. */
export async function declarations(
  root = new URL("file:///workspace/packages/"),
) {
  return (await read(root, "auth.toml", action, true)).map((
    { name, description, audit },
  ) => ({
    action: name,
    description,
    ...(audit === undefined ? {} : { audit }),
  }));
}

/** Parse one package's `auth.toml`: text, or `{ description, audit }`. */
export function parseActionDeclarations(text: string) {
  return Object.entries(parse(text)).map(([name, value]) => ({
    action: action.parse(name),
    ...entry(value, true),
  }));
}

/**
 * Whether a successful check of the action is audited: platform (`the8020.`)
 * operations except `view`, and other packages' actions only when declared
 * with `audit = true`. A declared `audit` always wins. Flags come from the
 * database (indexed with packages), so checks read no package files; they are
 * reread at most once a minute per worker.
 */
export async function audited(name: string): Promise<boolean> {
  if (auditCache === undefined || Date.now() - auditCache.at > AUDIT_CACHE_MS) {
    const flags = import("../tables/audit_flags.ts").then(
      async ({ default: AuditFlags }) =>
        new Map(
          (await AuditFlags.select(["action", "audit"]).execute()).map((
            row,
          ) => [row.action, Boolean(row.audit)]),
        ),
    );
    auditCache = { at: Date.now(), flags };
    // A failed read is retried on the next check.
    flags.catch(() => {
      if (auditCache?.flags === flags) auditCache = undefined;
    });
  }
  return (await auditCache.flags).get(name) ??
    (name.startsWith("the8020.") && name.split(".").at(-1) !== "view");
}

/** Forget cached flags, for tests and right after indexing. */
export function resetAuditCache(): void {
  auditCache = undefined;
}

const AUDIT_CACHE_MS = 60_000;
let auditCache:
  | { at: number; flags: Promise<Map<string, boolean>> }
  | undefined;

/** Advisory attribute declarations offered when editing roles and assignments. */
export async function attributeDeclarations(
  root = new URL("file:///workspace/packages/"),
) {
  return (await read(root, "auth-attributes.toml", attributeName)).map((
    { name, description },
  ) => ({ attribute: name, description }));
}

async function read(
  root: URL,
  fileName: string,
  key: { parse(value: unknown): string },
  tables = false,
) {
  const files: URL[] = [];
  for await (const namespace of Deno.readDir(root)) {
    if (!namespace.isDirectory || namespace.name.startsWith(".")) continue;
    const owner = new URL(`${encodeURIComponent(namespace.name)}/`, root);
    for await (const pkg of Deno.readDir(owner)) {
      if (pkg.isDirectory && !pkg.name.startsWith(".")) {
        files.push(
          new URL(
            `${encodeURIComponent(pkg.name)}/declarations/${fileName}`,
            owner,
          ),
        );
      }
    }
  }
  const rows: { name: string; description: string; audit?: boolean }[] = [];
  for (let offset = 0; offset < files.length; offset += 32) {
    const batch = await Promise.all(
      files.slice(offset, offset + 32).map(async (file) => {
        try {
          if ((await Deno.stat(file)).size > 1 << 20) {
            throw new Error("Declaration exceeds 1 MiB");
          }
          return Object.entries(parse(await Deno.readTextFile(file))).map((
            [name, value],
          ) => ({ name: key.parse(name), ...entry(value, tables) }));
        } catch (error) {
          if (!(error instanceof Deno.errors.NotFound)) {
            console.warn(
              `Cannot read authorization declarations ${file.pathname}: ${error}`,
            );
          }
          return [];
        }
      }),
    );
    rows.push(...batch.flat());
  }
  return rows.sort((a, b) =>
    a.name < b.name
      ? -1
      : a.name > b.name
      ? 1
      : a.description.localeCompare(b.description)
  );
}

/** A declaration is its description, or (for actions) `{ description, audit }`. */
function entry(value: unknown, tables: boolean) {
  if (!tables || typeof value === "string") {
    return { description: role.shape.description.parse(value) };
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("A declaration must be text or a table");
  }
  const record = value as Record<string, unknown>;
  const unknown = Object.keys(record).find((name) =>
    !["description", "audit"].includes(name)
  );
  if (unknown !== undefined) {
    throw new TypeError(`Unknown declaration key ${unknown}`);
  }
  if (record.audit !== undefined && typeof record.audit !== "boolean") {
    throw new TypeError("audit must be true or false");
  }
  return {
    description: role.shape.description.parse(record.description),
    ...(record.audit === undefined ? {} : { audit: record.audit }),
  };
}
