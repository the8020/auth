import { AdminCommandError } from "@the8020/kernel";
import { db } from "/p/the8020/db/mod.ts";
import { z } from "/p/the8020/db/fields.ts";
import Settings from "/p/the8020/system/tables/settings.ts";
import Grants from "../tables/grants.ts";
import Failures from "../tables/failures.ts";
import { requirePermission } from "./check.ts";

/** Days audited successes and denials are kept; stored in system settings. */
export const RETENTION_KEY = "auth.audit_retention_days";
export const DEFAULT_RETENTION_DAYS = 30;
export const retentionDays = z.number().int().min(1).max(3650);
/** Rows one cleanup statement removes, keeping each transaction short. */
const CLEANUP_BATCH = 1000;

/** The configured retention, or the default; never checks permissions. */
async function storedRetention(): Promise<number> {
  const row = await db.selectFrom(Settings.table).select("value").where(
    "key",
    "=",
    RETENTION_KEY,
  ).executeTakeFirst();
  const parsed = retentionDays.safeParse(row?.value);
  return parsed.success ? parsed.data : DEFAULT_RETENTION_DAYS;
}

export async function auditRetention(): Promise<number> {
  await requirePermission("the8020.auth.audit.view", "");
  return await storedRetention();
}

export async function setAuditRetention(days: number): Promise<number> {
  await requirePermission("the8020.auth.audit.edit", "");
  const parsed = retentionDays.safeParse(days);
  if (!parsed.success) {
    throw new AdminCommandError({
      code: "invalid_arguments",
      message: "retention must be 1–3650 days",
    });
  }
  const values = {
    value: parsed.data,
    definitionHash: "the8020/auth",
    updatedAt: new Date(),
  };
  await db.insertInto(Settings.table).values({ key: RETENTION_KEY, ...values })
    .onConflict((conflict) => conflict.column("key").doUpdateSet(values))
    .execute();
  return parsed.data;
}

/** Latest audited successful checks, newest first, 100 per page. */
export async function grantedChecks(username?: string, offset = 0) {
  z.number().int().nonnegative().parse(offset);
  await requirePermission("the8020.auth.audit.view", username ?? "");
  return await Grants.selectAll().$if(
    username !== undefined,
    (q) => q.where("username", "=", username!),
  ).orderBy("checkedAt", "desc").orderBy("id", "desc").offset(offset).limit(100)
    .execute();
}

/**
 * Delete audited successes and denials older than the retention, in short
 * batches. Run daily by the static `cleanup-audit` job.
 */
export async function cleanupAudit(now = new Date()) {
  await requirePermission("the8020.auth.audit.edit", "");
  const days = await storedRetention();
  const cutoff = new Date(now.getTime() - days * 86_400_000);
  const removed = { days, grants: 0, failures: 0 };
  for (
    const [name, table] of [["grants", Grants], ["failures", Failures]] as const
  ) {
    while (true) {
      const ids = (await db.selectFrom(table.table).select("id").where(
        "checkedAt",
        "<",
        cutoff,
      ).orderBy("checkedAt").limit(CLEANUP_BATCH).execute()).map((row) =>
        row.id
      );
      if (!ids.length) break;
      await db.deleteFrom(table.table).where("id", "in", ids).execute();
      removed[name] += ids.length;
      if (ids.length < CLEANUP_BATCH) break;
    }
  }
  return removed;
}
