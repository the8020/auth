import { t, table, type TableDatabase } from "/p/the8020/db/mod.ts";
import { assignment } from "../types/auth.ts";
import Roles from "./roles.ts";
import Users from "/p/the8020/users/tables/users.ts";
const UserRoles = table("the8020__auth__user_roles", {
  username: t.from(assignment.shape.username).primaryKey().references(() =>
    Users.username
  ),
  role: t.from(assignment.shape.role).primaryKey().references(() => Roles.name),
}, { indexes: [{ columns: ["role"] }] });
declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof UserRoles> {}
}
export default UserRoles;
