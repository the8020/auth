import { t, table, type TableDatabase } from "/p/the8020/db/mod.ts";
import { role } from "../types/auth.ts";
const Roles = table("the8020__auth__roles", {
  name: t.from(role.shape.name).primaryKey(),
  description: t.from(role.shape.description).default(""),
  permissions: t.from(role.shape.permissions).default({}),
});
declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof Roles> {}
}
export default Roles;
