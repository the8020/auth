import { field, z } from "/p/the8020/db/fields.ts";
import { username } from "/p/the8020/users/types/user.ts";
import { expression, pattern } from "../src/matching.ts";

/** Same character set as declared action names; attributes never use patterns. */
export const attributeName: z.ZodString = field(
  z.string().min(1).max(512).regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/),
  {
    label: "Attribute",
    description:
      "A declared authorization attribute, such as `dlis.einvoice.channel`. Its values come from each role assignment.",
    valueHelp: async (request) => {
      const { attributeDeclarations } = await import("../src/declarations.ts");
      const { queryValueHelp } = await import("/p/the8020/uui/lists.ts");
      return queryValueHelp(
        z.object({
          attribute: attributeName,
          description: role.shape.description,
        }),
        await attributeDeclarations(),
        request,
      );
    },
  },
);

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
    // Several values; escaping keeps a chosen literal out of the grammar.
    multiple: { separator: ",", escape: "-*?!<>" },
    label: "Allowed values",
    description:
      "Comma-separated values, inclusive ranges, `*`/`?` patterns and `!` exclusions. Enable Comparisons to use `>`, `>=`, `<`, `<=`; `!>`, `!>=`, `!<`, `!<=` then mean `<=`, `<`, `>=`, `>` and grant on their own. Numeric endpoints compare exact decimals; other endpoints compare case-sensitive text. Example with Comparisons enabled: `>=7000,!8000-8200`. Escape leading comparison punctuation for literals in that mode. With Comparisons off, `<` and `>` keep their literal meaning.",
  },
);
/** A value expression: plain or `{ comparisons }`; valid in roles and assignments. */
export const expressionValues = z.union([
  valueExpression,
  z.object({ comparisons: valueExpression }).strict(),
]).superRefine((source, ctx) => {
  try {
    expression(source);
  } catch (error) {
    ctx.addIssue({ code: "custom", message: String(error) });
  }
});
/** What a role entry stores: an expression, or an attribute bound by assignment. */
export const values = z.union([
  expressionValues,
  z.object({ attribute: attributeName }).strict(),
]);
/** Attribute values given to one role assignment. */
export const assignmentAttributes = field(
  z.record(attributeName, expressionValues).refine(
    (value) => Object.keys(value).length <= 64,
    "An assignment supports up to 64 attributes",
  ),
  {
    label: "Attribute values",
    description:
      "Values for the attributes referenced by the assigned role and the roles it includes, for example `dlis.einvoice.channel` = `SK,CZ`.",
    storage: { type: "json" },
  },
);
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
/** Where a package-declared role or a copy of one comes from. */
export const roleOrigin = {
  managed: field(z.string().max(200), {
    label: "Managed by",
    description:
      "The package that declares this role. Only its declaration changes the role; copy it to make your own version.",
  }),
  managedCommit: field(z.string().max(64), {
    label: "Package commit",
    description: "The package commit whose declaration the role matches.",
  }),
  collection: field(z.boolean(), {
    label: "Collection",
    description: "Groups other roles through inclusion.",
  }),
  obsolete: field(z.boolean(), {
    label: "Obsolete",
    description:
      "No longer declared by its package; kept while users or roles still use it.",
  }),
  copiedFrom: field(
    z.object({
      role: roleName,
      package: z.string().max(200),
      commit: z.string().max(64),
    }),
    {
      label: "Copied from",
      description: "The package role and commit this role was copied from.",
      storage: { type: "json" },
    },
  ),
};
export const assignment = z.object({
  username,
  role: roleName,
  attributes: assignmentAttributes.default({}),
});
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

/** One audited successful authorization check. */
export const grant = z.object({
  id: field(z.string(), {
    label: "Check ID",
    description: "Identifies this successful authorization check.",
  }),
  username,
  action,
  value,
  checkedAt: field(z.date(), {
    label: "Checked at",
    description: "When access was granted (UTC).",
  }),
  role: field(z.string(), {
    label: "Granted by",
    description: "The first reachable role whose entry allowed the check.",
  }),
});
