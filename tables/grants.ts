import { columns, table, type TableDatabase } from "/p/the8020/db/mod.ts";
import { grant } from "../types/auth.ts";
const fields = columns(grant);
const Grants = table("the8020__auth__grants", {
  ...fields,
  id: fields.id.primaryKey(),
}, {
  indexes: [{ columns: ["checkedAt", "id"] }, {
    columns: ["username", "checkedAt", "id"],
  }],
});
declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof Grants> {}
}
export default Grants;
