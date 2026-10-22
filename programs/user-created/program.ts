import { z } from "/p/the8020/db/fields.ts";
import { username } from "/p/the8020/users/types/user.ts";
import { assignDefaultRoles } from "../../src/defaults.ts";

const createdUser = z.object({
  name: z.literal("users.created"),
  data: z.object({ username }),
});

export default async function run(event: unknown): Promise<void> {
  await assignDefaultRoles(createdUser.parse(event).data.username);
}
