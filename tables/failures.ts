import { columns, table, type TableDatabase } from "/p/the8020/db/mod.ts";
import { failure } from "../types/auth.ts";
const fields = columns(failure);
const Failures = table("the8020__auth__failures", {
  ...fields,
  id: fields.id.primaryKey(),
}, {
  indexes: [{ columns: ["checkedAt", "id"] }, {
    columns: ["username", "checkedAt", "id"],
  }],
});
declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof Failures> {}
}
export default Failures;
