import { field, z } from "/p/the8020/db/fields.ts";
import { username } from "/p/the8020/users/types/user.ts";
import { expression, pattern } from "../src/matching.ts";

export const roleName: z.ZodString = field(
  z.string().min(1).max(200).refine((value) => !/[\p{Cc}]/u.test(value)),
  {
    label: "Role",
    description:
      "A unique, case-sensitive role name. A role matching a username is automatically assigned to that user.",
    valueHelp: async (request) => {
      const { default: Roles } = await import("../tables/roles.ts");
      const { lookupPage } = await import("/p/the8020/db/lookup.ts");
      return lookupPage(
        role.pick({ name: true, description: true }),
        Roles.select(["name", "description"]),
        request,
      );
    },
    open: async (value) => {
      const { default: roles } = await import("../programs/roles/program.ts");
      await roles(value);
    },
  },
);

export const action: z.ZodString = field(z.string().min(1).max(512), {
  label: "Action",
  description:
    "The authorization key, such as `sales.customer.edit`. Patterns use `*` for any text and `?` for one character; backslash escapes literal punctuation.",
  valueHelp: async (request) => {
    const { declarations } = await import("../src/declarations.ts");
    const { queryValueHelp } = await import("/p/the8020/uui/lists.ts");
    return queryValueHelp(
      z.object({ action, description: role.shape.description }),
      await declarations(),
      request,
    );
  },
});
export const value = field(z.string().max(2048), {
  label: "Value",
  description: "The single object identifier or value being authorized.",
});
const valueExpression = field(
  z.string().min(1).max(8192),
  {
    label: "Allowed values",
    description:
      "Comma-separated values, inclusive ranges, `*`/`?` patterns and `!` exclusions. Enable Comparisons to use `>`, `>=`, `<`, `<=`; `!>`, `!>=`, `!<`, `!<=` then mean `<=`, `<`, `>=`, `>` and grant on their own. Numeric endpoints compare exact decimals; other endpoints compare case-sensitive text. Example with Comparisons enabled: `>=7000,!8000-8200`. Escape leading comparison punctuation for literals in that mode. With Comparisons off, `<` and `>` keep their literal meaning.",
  },
);
export const values = z.union([
  valueExpression,
  z.object({ comparisons: valueExpression }).strict(),
]).superRefine((source, ctx) => {
  try {
    expression(source);
  } catch (error) {
    ctx.addIssue({ code: "custom", message: String(error) });
  }
});
export const permission = z.object({
  action,
  values: valueExpression,
  comparisons: field(z.boolean().default(false), {
    label: "Comparisons",
    description:
      "Interpret leading `<`, `>`, `!<` and `!>` as comparison operators. Existing entries keep this off until explicitly changed.",
  }),
});
export const permissions = field(
  z.record(
    action.superRefine((source, ctx) => {
      try {
        pattern(source);
      } catch (error) {
        ctx.addIssue({ code: "custom", message: String(error) });
      }
    }),
    values,
  ).refine(
    (value) => Object.keys(value).length <= 256,
    "A role supports up to 256 entries",
  ),
  { storage: { type: "json" } },
);
export const role = z.object({
  name: roleName,
  description: field(z.string().max(2000), {
    label: "Description",
    description: "What this role or authorization action is for.",
  }),
  permissions,
});
export const assignment = z.object({ username, role: roleName });
export const inclusion = z.object({ role: roleName, included: roleName });
export const failure = z.object({
  id: field(z.string(), {
    label: "Check ID",
    description: "Identifies this failed authorization check.",
  }),
  username,
  action,
  value,
  checkedAt: field(z.date(), {
    label: "Checked at",
    description: "When access was denied (UTC).",
  }),
  reason: field(
    z.enum(["no_roles", "no_action_match", "value_not_allowed", "role_limit"]),
    { label: "Reason", description: "Why no reachable role granted access." },
  ),
  details: field(
    z.array(
      z.object({
        role: z.string(),
        action: z.string().optional(),
        reason: z.string(),
      }),
    ),
    {
      label: "Details",
      description: "Evaluation evidence, limited to the first 100 entries.",
      storage: { type: "json" },
    },
  ),
});
