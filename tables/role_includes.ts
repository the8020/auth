import { t, table, type TableDatabase } from "/p/the8020/db/mod.ts";
import { inclusion } from "../types/auth.ts";
import Roles from "./roles.ts";
const RoleIncludes = table("the8020__auth__role_includes", {
  role: t.from(inclusion.shape.role).primaryKey().references(() => Roles.name),
  included: t.from(inclusion.shape.included).primaryKey().references(() =>
    Roles.name
  ),
}, { indexes: [{ columns: ["included"] }] });
declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof RoleIncludes> {}
}
export default RoleIncludes;
