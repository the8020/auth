import { z } from "/p/the8020/db/fields.ts";
import { username } from "/p/the8020/users/types/user.ts";
import { removeUserRoles } from "../../src/admin.ts";

const deletedUser = z.object({
  name: z.literal("users.deleted"),
  data: z.object({ username }),
});

export default async function run(event: unknown): Promise<void> {
  await removeUserRoles(deletedUser.parse(event).data.username);
}
