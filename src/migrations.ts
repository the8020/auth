import { db } from "/p/the8020/db/mod.ts";
import Roles from "../tables/roles.ts";

/** Platform packages whose actions moved under the `the8020.` namespace. */
const PLATFORM_PACKAGES = new Set([
  "auth",
  "deployments",
  "https",
  "packages",
  "services",
  "system",
  "users",
]);

/** `users.user.edit` → `the8020.users.user.edit`; other keys stay. */
export function namespacedAction(key: string): string {
  return PLATFORM_PACKAGES.has(key.split(".")[0]!) ? `the8020.${key}` : key;
}

/**
 * Rename platform action keys in stored roles, including patterns such as
 * `users.user.*`. Safe to repeat. When a role already holds the new key, that
 * entry wins and the old one is dropped.
 */
export async function migratePlatformActions(): Promise<{ roles: number }> {
  let roles = 0;
  await db.transaction().execute(async (tx) => {
    const rows = await tx.selectFrom(Roles.table).select([
      "name",
      "permissions",
    ]).execute();
    for (const row of rows) {
      const entries = Object.entries(row.permissions);
      if (!entries.some(([key]) => namespacedAction(key) !== key)) continue;
      const migrated: typeof row.permissions = {};
      for (const [key, values] of entries) {
        if (namespacedAction(key) === key) migrated[key] = values;
      }
      for (const [key, values] of entries) {
        const renamed = namespacedAction(key);
        if (renamed !== key && !Object.hasOwn(migrated, renamed)) {
          migrated[renamed] = values;
        }
      }
      await tx.updateTable(Roles.table).set({ permissions: migrated }).where(
        "name",
        "=",
        row.name,
      ).execute();
      roles++;
    }
  });
  return { roles };
}
