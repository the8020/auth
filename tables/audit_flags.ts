import { t, table, type TableDatabase } from "/p/the8020/db/mod.ts";

/** Declared `audit` overrides, indexed from each package's `auth.toml`. */
const AuditFlags = table("the8020__auth__audit_flags", {
  action: t.text().primaryKey(),
  packageId: t.text(),
  audit: t.boolean(),
}, { indexes: [{ columns: ["packageId"] }] });
declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof AuditFlags> {}
}
export default AuditFlags;
