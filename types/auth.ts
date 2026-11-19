import { msg } from "/p/the8020/auth/i18n/messages.ts";
import { field, z } from "/p/the8020/db/fields.ts";
import { username } from "/p/the8020/users/types/user.ts";
import { expression, pattern } from "../src/matching.ts";

/** Same character set as declared action names; attributes never use patterns. */
export const attributeName: z.ZodString = field(
  z.string().min(1).max(512).regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/),
  {
    label: msg("screens.attribute"),
    description: msg("auth.a_declared_authorization_attribute_such_as_dlis"),
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
    label: msg("auth.role"),
    description: msg("auth.a_unique_case_sensitive_role_name_a"),
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
  label: msg("auth.action"),
  description: msg("auth.the_authorization_key_such_as_sales_customer"),
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
  label: msg("auth.value"),
  description: msg("auth.the_single_object_identifier_or_value_being"),
});
const valueExpression = field(z.string().min(1).max(8192), {
  label: msg("auth.allowed_values"),
  description: msg("auth.allowed_values_help"),
});
/** Automatic syntax, including the object form of previously stored entries. */
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
    { params: { text: msg("errors.assignment_attribute_limit") } },
  ),
  {
    label: msg("screens.attribute_values"),
    description: msg("auth.values_for_the_attributes_referenced_by_the"),
    storage: { type: "json" },
  },
);
export const permission = z.object({
  action,
  values: valueExpression,
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
    label: msg("auth.description"),
    description: msg("auth.what_this_role_or_authorization_action_is"),
  }),
  permissions,
});
/** Where a package-declared role or a copy of one comes from. */
export const roleOrigin = {
  managed: field(z.string().max(200), {
    label: msg("auth.managed_by"),
    description: msg("auth.the_package_that_declares_this_role_only"),
  }),
  managedCommit: field(z.string().max(64), {
    label: msg("auth.package_commit"),
    description: msg("auth.the_package_commit_whose_declaration_the_role"),
  }),
  collection: field(z.boolean(), {
    label: msg("auth.collection"),
    description: msg("auth.groups_other_roles_through_inclusion"),
  }),
  obsolete: field(z.boolean(), {
    label: msg("auth.obsolete"),
    description: msg("auth.no_longer_declared_by_its_package_kept"),
  }),
  copiedFrom: field(
    z.object({
      role: roleName,
      package: z.string().max(200),
      commit: z.string().max(64),
    }),
    {
      label: msg("screens.copied_from"),
      description: msg("screens.the_package_role_and_commit_this_role"),
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
    label: msg("auth.check_id"),
    description: msg("auth.identifies_this_failed_authorization_check"),
  }),
  username,
  action,
  value,
  checkedAt: field(z.date(), {
    label: msg("auth.checked_at"),
    description: msg("auth.when_access_was_denied_utc"),
  }),
  reason: field(
    z.enum(["no_roles", "no_action_match", "value_not_allowed", "role_limit"]),
    {
      label: msg("auth.reason"),
      description: msg("auth.why_no_reachable_role_granted_access"),
    },
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
      label: msg("screens.details"),
      description: msg("auth.evaluation_evidence_limited_to_the_first_100"),
      storage: { type: "json" },
    },
  ),
});

/** One audited successful authorization check. */
export const grant = z.object({
  id: field(z.string(), {
    label: msg("auth.check_id"),
    description: msg("auth.identifies_this_successful_authorization_check"),
  }),
  username,
  action,
  value,
  checkedAt: field(z.date(), {
    label: msg("auth.checked_at"),
    description: msg("auth.when_access_was_granted_utc"),
  }),
  role: field(z.string(), {
    label: msg("auth.granted_by"),
    description: msg("auth.the_first_reachable_role_whose_entry_allowed"),
  }),
});
