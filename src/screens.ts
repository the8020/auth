import { metadataText } from "/p/the8020/packages/localization.ts";
import { text as localizedText } from "/p/the8020/i18n/mod.ts";
import { msg } from "/p/the8020/auth/i18n/messages.ts";
import {
  BACK_EVENT,
  callScreen,
  confirmAction,
  describeError,
  field,
  Model,
  presentModal,
  presentPage,
  sendMessage,
  z,
} from "/p/the8020/uui/mod.ts";
import { username } from "/p/the8020/users/types/user.ts";
import {
  attributeName,
  failure,
  grant,
  permission,
  role,
  roleName,
  roleOrigin,
} from "../types/auth.ts";
import { isAttributeReference, type PermissionValues } from "./matching.ts";
import * as admin from "./admin.ts";
import * as audit from "./audit.ts";
import * as defaults from "./defaults.ts";

const automatic = field(z.boolean(), {
  label: msg("screens.automatic"),
  description: msg("screens.granted_because_this_role_name_matches_the"),
});
const roleRow = z.object({ role: roleName, automatic, explicit: z.boolean() });
/** An entry takes its values either from the expression or from an attribute. */
const permissionEntry = permission.extend({
  values: permission.shape.values.optional(),
  attribute: field(attributeName.optional(), {
    label: msg("screens.attribute"),
    description: msg("screens.take_the_allowed_values_from_this_attribute"),
  }),
});
/** Short syntax help under Allowed values; the field keeps its full grammar. */
const VALUES_HELP = msg(
  "screens.comma_separated_values_inclusive_ranges_patterns_and",
);
const attributeRow = z.object({
  attribute: attributeName,
  values: permission.shape.values.optional(),
});
const userRow = z.object({ username, automatic, explicit: z.boolean() });
function error(value: unknown) {
  sendMessage(describeError(value), "error");
}

async function pick(
  title: string,
  schema: z.ZodString,
): Promise<string | undefined> {
  const model = new Model<{ value?: string }>({});
  while (true) {
    const event = await callScreen({
      id: "auth-pick",
      title,
      schema: z.object({ value: schema.optional() }),
      model,
      controls: [{ bind: "value", length: "long" }],
      header: {
        actions: [{ id: "save", label: msg("screens.add"), kind: "primary" }],
      },
    });
    if (event.action === BACK_EVENT) return;
    if (event.action === "save" && model.data.value) return model.data.value;
  }
}

/** Shared UUI confirmation: short title, consequence as body text. */
function confirm(
  title: string,
  message: string,
  label = localizedText(msg("ui.delete")),
  kind: "danger" | "primary" = "danger",
): Promise<boolean> {
  return confirmAction({
    id: "auth-confirm",
    title,
    message,
    confirm: label,
    kind,
  });
}

export async function roles(selected?: string): Promise<void> {
  if (selected !== undefined) return await roleDetail(selected);
  const schema = z.object({
    roles: role.pick({ name: true, description: true }).extend({
      managed: roleOrigin.managed,
      collection: roleOrigin.collection,
      obsolete: roleOrigin.obsolete,
    }).array(),
  });
  const model = new Model<z.infer<typeof schema>>({ roles: [] });
  while (true) {
    model.data.roles = await Promise.all(
      (await admin.listRoles()).map(async (row) => ({
        ...row,
        description: row.managed
          ? await metadataText(
            row.managed,
            `declarations.auth-roles.${row.name}`,
            row.description,
          )
          : row.description,
        managed: row.managed ?? "",
      })),
    );
    const event = await callScreen({
      id: "auth-roles",
      title: msg("screens.roles"),
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-roles",
        root: {
          toolbar: [{
            id: "add",
            label: msg("screens.create_role"),
            kind: "primary",
          }, {
            id: "refresh",
            label: msg("screens.refresh"),
          }],
          type: "list",
          bind: "roles",
          key: "name",
          display: ["name", "description", "managed", "collection", "obsolete"],
          columnOptions: { description: { length: "long" } },
        },
      },
      header: {
        actions: [{ id: "defaults", label: msg("screens.default_roles") }, {
          id: "audit",
          label: msg("screens.audit"),
        }, {
          id: "failures",
          label: msg("screens.failed_checks"),
        }],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "add") {
        const name = await presentModal(() => editRole());
        if (name !== undefined) await presentPage(() => roleDetail(name));
      }
      if (event.action === "select" && typeof event.value === "string") {
        await presentPage(() => roleDetail(String(event.value)));
      }
      if (event.action === "failures") await presentPage(() => failures());
      if (event.action === "audit") await presentPage(() => auditLog());
      if (event.action === "defaults") {
        await presentPage(() => defaultRolesScreen());
      }
    } catch (e) {
      error(e);
    }
  }
}

async function editRole(
  existing?: z.infer<typeof role> & { collection?: boolean },
): Promise<string | undefined> {
  const schema = role.pick({ name: true, description: true }).extend({
    collection: roleOrigin.collection,
  });
  const model = new Model({
    name: existing?.name,
    description: existing?.description ?? "",
    collection: existing?.collection ?? false,
  });
  while (true) {
    const event = await callScreen({
      id: "auth-role-edit",
      title: existing
        ? localizedText(msg("ui.edit_role"))
        : localizedText(msg("ui.create_role")),
      schema: schema.partial({ name: true }),
      model,
      controls: [{ bind: "name", readOnly: !!existing, length: "long" }, {
        bind: "description",
        length: "long",
      }, { bind: "collection" }],
      header: {
        actions: [{
          id: "save",
          label: msg("screens.save_role"),
          kind: "primary",
        }],
      },
    });
    if (event.action === BACK_EVENT) return;
    if (event.action !== "save") continue;
    try {
      const saved = await (existing ? admin.saveRole : admin.createRole)({
        ...schema.parse(model.data),
        permissions: existing?.permissions ?? {},
      });
      return saved.name;
    } catch (e) {
      sendMessage(describeError(e, schema), "error");
    }
  }
}

const templateChange = z.object({
  key: field(z.string(), {
    label: msg("screens.action_or_role"),
    description: msg("screens.the_permission_action_or_included_role_that"),
  }),
  kind: field(z.string(), {
    label: msg("screens.kind"),
    description: msg("screens.whether_a_permission_or_an_included_role"),
  }),
  change: field(z.string(), {
    label: msg("screens.change"),
    description: msg("screens.added_or_removed_in_the_template_since"),
  }),
  template: field(z.string(), {
    label: msg("screens.template"),
    description: msg("screens.the_template_s_current_values"),
  }),
  copy: field(z.string(), {
    label: msg("screens.this_copy"),
    description: msg("screens.this_role_s_values"),
  }),
});

async function roleDetail(name: string): Promise<void> {
  const schema = role.pick({ name: true, description: true }).extend({
    managed: roleOrigin.managed,
    collection: roleOrigin.collection,
    obsolete: roleOrigin.obsolete,
    copiedFrom: field(z.string(), {
      label: msg("screens.copied_from"),
      description: msg("screens.the_package_role_and_commit_this_role"),
    }),
    entries: permissionEntry.array(),
    changes: templateChange.array(),
  });
  const model = new Model<z.infer<typeof schema>>({
    name,
    description: "",
    managed: "",
    collection: false,
    obsolete: false,
    copiedFrom: "",
    entries: [],
    changes: [],
  });
  while (true) {
    const record = await admin.getRole(name);
    const managed = Boolean(record.managed);
    const template = record.copiedFrom
      ? await admin.templateChanges(name)
      : undefined;
    model.data.description = record.managed
      ? await metadataText(
        record.managed,
        `declarations.auth-roles.${record.name}`,
        record.description,
      )
      : record.description;
    model.data.managed = record.managed ?? "";
    model.data.collection = record.collection;
    model.data.obsolete = record.obsolete;
    model.data.copiedFrom = record.copiedFrom
      ? `${record.copiedFrom.role} (${record.copiedFrom.package} ${
        record.copiedFrom.commit.slice(0, 12)
      })${template?.missing ? " · template removed" : ""}`
      : "";
    model.data.changes = (template?.changes ?? []).map((item) => ({
      key: item.key,
      kind: item.kind,
      change: item.change,
      template: item.template ?? "",
      copy: item.copy ?? "",
    }));
    model.data.entries = Object.entries(record.permissions).map((
      [action, values],
    ) =>
      isAttributeReference(values) ? { action, attribute: values.attribute } : {
        action,
        values: typeof values === "string" ? values : values.comparisons,
      }
    );
    const origin = [
      "managed",
      ...(record.copiedFrom ? ["copiedFrom"] : []),
      "collection",
      ...(record.obsolete ? ["obsolete"] : []),
    ];
    const event = await callScreen({
      id: "auth-role",
      title: msg("screens.role_name", { name: name }),
      schema,
      model,
      controls: [
        { bind: "name", readOnly: true },
        { bind: "description", readOnly: true, length: "long" },
        { bind: "managed", readOnly: true, hidden: !managed },
        { bind: "copiedFrom", readOnly: true, length: "long" },
        { bind: "collection", readOnly: true },
        { bind: "obsolete", readOnly: true },
      ],
      layout: {
        schema: 1,
        id: "auth-role",
        root: {
          type: "stack",
          children: [
            {
              type: "detail",
              controls: [
                "name",
                "description",
                ...origin.filter((item) => item !== "managed" || managed),
              ],
            },
            {
              toolbar: managed ? [] : [{
                id: "permission",
                label: msg("screens.add_permission"),
                kind: "primary",
              }],
              type: "list",
              title: msg("screens.permissions"),
              bind: "entries",
              key: "action",
              display: ["action", "values", "attribute"],
            },
            ...(record.copiedFrom
              ? [{
                toolbar: model.data.changes.length
                  ? [{
                    id: "adopt",
                    label: msg("screens.adopt_template_changes"),
                    kind: "primary" as const,
                  }]
                  : [],
                type: "list",
                title: msg("screens.changes_in_the_template"),
                bind: "changes",
                key: "key",
                display: ["key", "kind", "change", "template", "copy"],
              }]
              : []),
          ],
        },
      },
      header: {
        actions: [
          { id: "included", label: msg("screens.included_roles") },
          { id: "users", label: msg("screens.users") },
          { id: "copy", label: msg("screens.copy_role") },
          ...(managed ? [] : [
            { id: "edit", label: msg("screens.edit_role") },
            {
              id: "delete",
              label: msg("screens.delete_role"),
              kind: "danger" as const,
            },
          ]),
          { id: "refresh", label: msg("screens.refresh") },
        ],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "permission") {
        await presentModal(() => editPermission(name));
      }
      if (
        event.action === "select" && event.bind === "entries" &&
        typeof event.value === "string"
      ) {
        const entry = model.data.entries.find((row) =>
          row.action === event.value
        );
        if (entry) {
          await presentModal(() => editPermission(name, entry, managed));
        }
      }
      if (event.action === "edit") await presentModal(() => editRole(record));
      if (event.action === "copy") {
        const target = await presentModal(() =>
          pick(localizedText(msg("ui.copy_as")), roleName)
        );
        if (target) {
          await admin.copyRole(name, target);
          await presentPage(() => roleDetail(target));
        }
      }
      if (
        event.action === "adopt" &&
        await confirm(
          localizedText(msg("screens.adopt_template_changes")),
          localizedText(
            msg(
              "ui.the_permissions_and_included_roles_of_value1_will_be_replaced_with_its_template_s",
              { value1: name },
            ),
          ),
          localizedText(msg("ui.adopt_changes")),
          "primary",
        )
      ) await admin.adoptTemplate(name);
      if (event.action === "included") {
        await presentPage(() => includedRoles(name));
      }
      if (event.action === "users") await presentPage(() => roleUsers(name));
      if (
        event.action === "delete" &&
        await confirm(
          localizedText(msg("screens.delete_role")),
          localizedText(
            msg("ui.role_value1_and_all_its_assignments_will_be_deleted", {
              value1: name,
            }),
          ),
          localizedText(msg("ui.delete_role")),
        )
      ) {
        await admin.deleteRole(name);
        return;
      }
    } catch (e) {
      error(e);
    }
  }
}

async function editPermission(
  name: string,
  existing?: z.infer<typeof permissionEntry>,
  managed = false,
): Promise<void> {
  const model = new Model<Partial<z.infer<typeof permissionEntry>>>(
    existing ? { ...existing } : {},
  );
  // Declarations explain each action's value; a missing one keeps defaults.
  const declared = new Map(
    (await import("./declarations.ts").then((module) => module.declarations())
      .catch(() => [])).map((item) => [item.action, item]),
  );
  while (true) {
    const declaration = model.data.action === undefined
      ? undefined
      : declared.get(model.data.action);
    const valueless = declaration?.value === false;
    const schema = permissionEntry.partial().extend({
      action: field(permissionEntry.shape.action.optional(), {
        reactive: true,
        ...(declaration === undefined ? {} : {
          description: msg("screens.value1_value2", {
            value1: declaration.description,
            value2: valueless
              ? localizedText(
                msg("ui.granted_as_a_whole_it_has_no_value_to_restrict"),
              )
              : "",
          }),
        }),
      }),
      values: field(permissionEntry.shape.values, {
        hidden: valueless,
        description: msg("screens.value1_values_help", {
          value1: declaration === undefined ? "" : localizedText(
            msg("ui.for_this_action_value1", {
              value1: declaration.description,
            }),
          ),
          VALUES_HELP: localizedText(VALUES_HELP),
        }),
      }),
      attribute: field(permissionEntry.shape.attribute, { hidden: valueless }),
    });
    const event = await callScreen({
      id: "auth-permission",
      title: msg("screens.permission_name", { name: name }),
      schema,
      model,
      controls: [
        { bind: "action", readOnly: !!existing, length: "long" },
        { bind: "values", readOnly: managed, length: "long" },
        { bind: "attribute", readOnly: managed, length: "long" },
      ],
      header: {
        actions: managed ? [] : [
          {
            id: "save",
            label: msg("screens.save_permission"),
            kind: "primary",
          },
          ...(existing
            ? [{
              id: "delete",
              label: msg("screens.delete_permission"),
              kind: "danger" as const,
            }]
            : []),
        ],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "save") {
        const data = permissionEntry.parse(model.data);
        if (valueless) {
          // Checked with an empty value, which `*` matches.
          await admin.setPermission(name, data.action, "*");
          return;
        }
        if (!data.attribute && !data.values) {
          throw new TypeError(
            localizedText(
              msg(
                "ui.enter_allowed_values_allows_every_value_or_choose_an_attribute",
              ),
            ),
          );
        }
        await admin.setPermission(
          name,
          data.action,
          data.attribute ? { attribute: data.attribute } : data.values!,
        );
        return;
      }
      if (
        existing && event.action === "delete" &&
        await confirm(
          localizedText(msg("screens.delete_permission")),
          localizedText(
            msg("ui.value1_will_be_removed_from_role_value2", {
              value1: existing.action,
              value2: name,
            }),
          ),
          localizedText(msg("ui.delete_permission")),
        )
      ) {
        await admin.setPermission(name, existing.action);
        return;
      }
    } catch (e) {
      error(e);
    }
  }
}

async function includedRoles(name: string): Promise<void> {
  const schema = z.object({ roles: z.object({ included: roleName }).array() });
  const model = new Model<z.infer<typeof schema>>({ roles: [] });
  while (true) {
    model.data.roles = await admin.includedRoles(name);
    const event = await callScreen({
      id: "auth-includes",
      title: msg("screens.included_roles_name", { name: name }),
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-includes",
        root: {
          toolbar: [{
            id: "add",
            label: msg("screens.include_role"),
            kind: "primary",
          }, {
            id: "refresh",
            label: msg("screens.refresh"),
          }],
          type: "list",
          bind: "roles",
          key: "included",
          display: ["included"],
        },
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "add") {
        const included = await presentModal(() =>
          pick(localizedText(msg("ui.include_role")), roleName)
        );
        if (included) await admin.includeRole(name, included);
      }
      if (event.action === "select" && typeof event.value === "string") {
        const included = event.value;
        await presentModal(async () => {
          const selected = await callScreen({
            id: "auth-included",
            title: msg("screens.included_role_included", {
              included: included,
            }),
            schema: z.object({ role: roleName }),
            model: new Model({ role: included }),
            controls: [{ bind: "role", readOnly: true }],
            header: {
              actions: [{ id: "open", label: msg("screens.open_role") }, {
                id: "remove",
                label: msg("screens.remove_inclusion"),
                kind: "danger",
              }],
            },
          });
          if (selected.action === "open") {
            await presentPage(() => roleDetail(included));
          }
          if (selected.action === "remove") {
            await admin.includeRole(name, included, false);
          }
        });
      }
    } catch (e) {
      error(e);
    }
  }
}

export async function userRoles(name: string): Promise<void> {
  const schema = z.object({ roles: roleRow.array() });
  const model = new Model<z.infer<typeof schema>>({ roles: [] });
  let attributesByRole = new Map<string, Record<string, PermissionValues>>();
  while (true) {
    const assigned = await admin.userRoles(name);
    attributesByRole = new Map(
      assigned.map((row) => [row.role, row.attributes]),
    );
    model.data.roles = assigned.map(({ attributes: _, ...row }) => row);
    const event = await callScreen({
      id: "auth-user-roles",
      title: msg("screens.roles_for_name", { name: name }),
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-user-roles",
        root: {
          toolbar: [{
            id: "add",
            label: msg("screens.assign_role"),
            kind: "primary",
          }, {
            id: "personal",
            label: msg("screens.personal_permissions"),
          }, { id: "refresh", label: msg("screens.refresh") }],
          type: "list",
          bind: "roles",
          key: "role",
          display: ["role", "automatic"],
        },
      },
      header: {
        actions: [{ id: "user", label: msg("screens.open_user") }, {
          id: "failures",
          label: msg("screens.failed_checks"),
        }],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "add") {
        const role = await presentModal(() =>
          pick(localizedText(msg("ui.assign_role")), roleName)
        );
        if (role) {
          await admin.assignRole(name, role);
          // A role referencing attributes needs their values right away.
          if ((await admin.roleAttributes(role)).length) {
            await presentModal(() => assignmentAttributes(name, role, {}));
          }
        }
      }
      if (event.action === "personal") {
        await admin.personalRole(name);
        await presentPage(() => roleDetail(name));
      }
      if (event.action === "user") await presentPage(() => openUser(name));
      if (event.action === "failures") await presentPage(() => failures(name));
      if (event.action === "select" && typeof event.value === "string") {
        const row = model.data.roles.find((row) => row.role === event.value)!;
        await presentModal(async () => {
          const selected = await callScreen({
            id: "auth-assignment",
            title: msg("screens.name_value2", { name: name, value2: row.role }),
            schema: roleRow,
            model: new Model(row),
            controls: [{ bind: "role", readOnly: true }, {
              bind: "automatic",
              readOnly: true,
            }],
            header: {
              actions: [
                { id: "open", label: msg("screens.open_role") },
                ...(row.explicit
                  ? [{
                    id: "attributes",
                    label: msg("screens.attribute_values"),
                  }]
                  : []),
                ...(row.explicit
                  ? [{
                    id: "remove",
                    label: msg("screens.remove_assignment"),
                    kind: "danger" as const,
                  }]
                  : []),
              ],
            },
          });
          if (selected.action === "open") {
            await presentPage(() => roleDetail(row.role));
          }
          if (row.explicit && selected.action === "attributes") {
            await assignmentAttributes(
              name,
              row.role,
              attributesByRole.get(row.role) ?? {},
            );
          }
          if (row.explicit && selected.action === "remove") {
            await admin.assignRole(name, row.role, false);
          }
        });
      }
    } catch (e) {
      error(e);
    }
  }
}

/** Edit the attribute values of one assignment; Save replaces them together. */
async function assignmentAttributes(
  username: string,
  roleName: string,
  stored: Record<string, PermissionValues>,
): Promise<void> {
  const schema = z.object({ attributes: attributeRow.array() });
  const referenced = await admin.roleAttributes(roleName);
  const names = Array.from(new Set([...referenced, ...Object.keys(stored)]))
    .sort();
  const model = new Model<z.infer<typeof schema>>({
    attributes: names.map((attribute) => {
      const values = stored[attribute];
      return {
        attribute,
        values: values === undefined
          ? undefined
          : typeof values === "string"
          ? values
          : values.comparisons,
      };
    }),
  });
  while (true) {
    const event = await callScreen({
      id: "auth-assignment-attributes",
      title: msg("screens.username_rolename_attribute_values", {
        username: username,
        roleName: roleName,
      }),
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-assignment-attributes",
        root: {
          type: "list",
          bind: "attributes",
          key: "attribute",
          display: ["attribute", "values"],
        },
      },
      header: {
        actions: [{
          id: "save",
          label: msg("screens.save_attribute_values"),
          kind: "primary",
        }],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "select" && typeof event.value === "string") {
        const row = model.data.attributes.find((item) =>
          item.attribute === event.value
        );
        if (row) {
          const edited = new Model({ ...row });
          const result = await presentModal(() =>
            callScreen({
              id: "auth-assignment-attribute",
              title: msg("screens.rolename_value2", {
                roleName: roleName,
                value2: row.attribute,
              }),
              schema: attributeRow,
              model: edited,
              controls: [
                { bind: "attribute", readOnly: true, length: "long" },
                {
                  bind: "values",
                  length: "long",
                },
              ],
              header: {
                actions: [{
                  id: "done",
                  label: msg("screens.done"),
                  kind: "primary",
                }],
              },
            })
          );
          if (result.action === "done") Object.assign(row, edited.data);
        }
      }
      if (event.action === "save") {
        const attributes: Record<string, PermissionValues> = {};
        for (const row of model.data.attributes) {
          if (!row.values) continue;
          attributes[row.attribute] = row.values;
        }
        await admin.assignRole(username, roleName, true, attributes);
        sendMessage(
          localizedText(msg("screens.attribute_values_saved")),
          "success",
        );
        return;
      }
    } catch (e) {
      error(e);
    }
  }
}

async function openUser(name: string): Promise<void> {
  const { default: users } = await import(
    "/p/the8020/users/programs/users/program.ts"
  );
  await users(name);
}

async function roleUsers(name: string): Promise<void> {
  const schema = z.object({ users: userRow.array() });
  const model = new Model<z.infer<typeof schema>>({ users: [] });
  while (true) {
    model.data.users = await admin.roleUsers(name);
    const event = await callScreen({
      id: "auth-role-users",
      title: msg("screens.users_with_name", { name: name }),
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-role-users",
        root: {
          toolbar: [{
            id: "add",
            label: msg("screens.assign_user"),
            kind: "primary",
          }, {
            id: "refresh",
            label: msg("screens.refresh"),
          }],
          type: "list",
          bind: "users",
          key: "username",
          display: ["username", "automatic"],
        },
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "add") {
        const user = await presentModal(() =>
          pick(localizedText(msg("ui.assign_user")), username)
        );
        if (user) {
          await admin.assignRole(user, name);
          if ((await admin.roleAttributes(name)).length) {
            await presentModal(() => assignmentAttributes(user, name, {}));
          }
        }
      }
      if (event.action === "select" && typeof event.value === "string") {
        const row = model.data.users.find((row) =>
          row.username === event.value
        )!;
        await presentModal(async () => {
          const selected = await callScreen({
            id: "auth-member",
            title: msg("screens.name_value2", {
              name: name,
              value2: row.username,
            }),
            schema: userRow,
            model: new Model(row),
            controls: [{ bind: "username", readOnly: true }, {
              bind: "automatic",
              readOnly: true,
            }],
            header: {
              actions: [
                { id: "open", label: msg("screens.open_user") },
                { id: "roles", label: msg("screens.user_roles") },
                ...(row.explicit
                  ? [{
                    id: "attributes",
                    label: msg("screens.attribute_values"),
                  }]
                  : []),
                ...(row.explicit
                  ? [{
                    id: "remove",
                    label: msg("screens.remove_assignment"),
                    kind: "danger" as const,
                  }]
                  : []),
              ],
            },
          });
          if (selected.action === "open") {
            await presentPage(() => openUser(row.username));
          }
          if (selected.action === "roles") {
            await presentPage(() => userRoles(row.username));
          }
          if (row.explicit && selected.action === "attributes") {
            const stored = (await admin.userRoles(row.username)).find((item) =>
              item.role === name
            )?.attributes ?? {};
            await assignmentAttributes(row.username, name, stored);
          }
          if (row.explicit && selected.action === "remove") {
            await admin.assignRole(row.username, name, false);
          }
        });
      }
    } catch (e) {
      error(e);
    }
  }
}

export async function failures(name?: string): Promise<void> {
  const schema = z.object({ failures: failure.array() });
  const model = new Model<z.infer<typeof schema>>({ failures: [] });
  let offset = 0;
  while (true) {
    model.data.failures = await admin.failedChecks(name, offset);
    const event = await callScreen({
      id: "auth-failures",
      title: name
        ? localizedText(msg("ui.failed_checks_value1", { value1: name }))
        : localizedText(msg("ui.failed_authorization_checks")),
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-failures",
        root: {
          toolbar: [
            { id: "refresh", label: msg("screens.refresh") },
            ...(offset
              ? [{ id: "previous", label: msg("screens.previous_100") }]
              : []),
            ...(model.data.failures.length === 100
              ? [{ id: "next", label: msg("screens.next_100") }]
              : []),
          ],
          type: "list",
          bind: "failures",
          key: "id",
          display: ["checkedAt", "username", "action", "value", "reason"],
        },
      },
    });
    if (event.action === BACK_EVENT) return;
    if (event.action === "previous") offset = Math.max(0, offset - 100);
    if (event.action === "next") offset += 100;
    if (event.action === "refresh") offset = 0;
    if (event.action === "select") {
      const row = model.data.failures.find((row) => row.id === event.value);
      if (!row) continue;
      await presentModal(async () => {
        const detail = failure.omit({ details: true }).extend({
          details: field(z.string(), {
            label: msg("screens.details"),
            control: "textarea",
            rowSpan: 8,
          }),
        });
        await callScreen({
          id: "auth-failure",
          title: msg("screens.failed_check"),
          schema: detail,
          model: new Model({
            ...row,
            details: row.details.map((entry) =>
              `${entry.role}${
                entry.action ? ` · ${entry.action}` : ""
              }: ${entry.reason}`
            ).join("\n"),
          }),
          controls: Object.keys(detail.shape).map((bind) => ({
            bind,
            readOnly: true,
            length: "long" as const,
          })),
        });
      });
    }
  }
}

const retention = field(audit.retentionDays, {
  label: msg("screens.keep_records_days"),
  description: msg("screens.audited_successes_and_failed_checks_older_than"),
});

/** Audited successful checks, newest first, with the shared retention. */
export async function auditLog(name?: string): Promise<void> {
  const schema = z.object({ grants: grant.array(), days: retention });
  const model = new Model<z.infer<typeof schema>>({ grants: [], days: 30 });
  let offset = 0;
  while (true) {
    try {
      model.data.grants = await audit.grantedChecks(name, offset);
      model.data.days = await audit.auditRetention();
    } catch (e) {
      error(e);
      return;
    }
    const event = await callScreen({
      id: "auth-audit",
      title: name
        ? localizedText(msg("ui.audit_name", { name }))
        : localizedText(msg("ui.authorization_audit")),
      schema,
      model,
      controls: [{ bind: "days", readOnly: true }],
      layout: {
        schema: 1,
        id: "auth-audit",
        root: {
          type: "stack",
          children: [{ type: "detail", controls: ["days"] }, {
            toolbar: [
              { id: "refresh", label: msg("screens.refresh") },
              { id: "retention", label: msg("screens.change_retention") },
              ...(offset
                ? [{ id: "previous", label: msg("screens.previous_100") }]
                : []),
              ...(model.data.grants.length === 100
                ? [{ id: "next", label: msg("screens.next_100") }]
                : []),
            ],
            type: "list",
            bind: "grants",
            key: "id",
            display: ["checkedAt", "username", "action", "value", "role"],
          }],
        },
      },
    });
    if (event.action === BACK_EVENT) return;
    if (event.action === "previous") offset = Math.max(0, offset - 100);
    if (event.action === "next") offset += 100;
    if (event.action === "refresh") offset = 0;
    if (event.action === "retention") {
      await presentModal(async () => {
        const edit = new Model({ days: model.data.days });
        while (true) {
          const result = await callScreen({
            id: "auth-retention",
            title: msg("screens.audit_retention"),
            schema: z.object({ days: retention }),
            model: edit,
            header: {
              actions: [{
                id: "save",
                label: msg("screens.save"),
                kind: "primary",
              }],
            },
          });
          if (result.action === BACK_EVENT) return;
          if (result.action !== "save") continue;
          try {
            await audit.setAuditRetention(edit.data.days);
            sendMessage(
              localizedText(
                msg("screens.records_are_kept_for_value1_days", {
                  value1: edit.data.days,
                }),
              ),
              "info",
            );
            return;
          } catch (e) {
            error(e);
          }
        }
      });
    }
  }
}

/** Read-only list of the signed-in user's own roles, for My account. */
export async function ownRoles(): Promise<void> {
  const schema = z.object({
    roles: z.object({
      role: roleName,
      description: role.shape.description,
      attributes: field(z.string(), {
        label: msg("screens.values"),
        description: msg("screens.attribute_values_given_with_this_assignment"),
      }),
    }).array(),
  });
  const model = new Model<z.infer<typeof schema>>({ roles: [] });
  while (true) {
    try {
      model.data.roles = (await admin.ownRoles()).map((row) => ({
        role: row.role,
        description: row.description,
        attributes: Object.entries(row.attributes).map(([name, values]) =>
          `${name} = ${
            typeof values === "string" ? values : values.comparisons
          }`
        ).join("; "),
      }));
    } catch (e) {
      error(e);
      return;
    }
    const event = await callScreen({
      id: "auth-own-roles",
      title: msg("screens.my_roles"),
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-own-roles",
        root: {
          toolbar: [{ id: "refresh", label: msg("screens.refresh") }],
          type: "list",
          bind: "roles",
          key: "role",
          display: ["role", "description", "attributes"],
          columnOptions: { description: { length: "long" } },
        },
      },
    });
    if (event.action === BACK_EVENT) return;
  }
}

/** The roles every new user receives, chosen together in one field. */
export async function defaultRolesScreen(): Promise<void> {
  const schema = z.object({
    roles: field(z.array(roleName).max(32), {
      label: msg("screens.default_roles"),
      description: msg("screens.every_new_user_receives_these_roles_existing"),
      length: "long",
    }),
  });
  const model = new Model<z.infer<typeof schema>>({ roles: [] });
  try {
    model.data.roles = await defaults.defaultRoles();
  } catch (e) {
    error(e);
    return;
  }
  while (true) {
    const event = await callScreen({
      id: "auth-default-roles",
      title: msg("screens.default_roles_of_new_users"),
      schema,
      model,
      header: {
        actions: [{ id: "save", label: msg("screens.save"), kind: "primary" }],
      },
    });
    if (event.action === BACK_EVENT) return;
    if (event.action !== "save") continue;
    try {
      model.data.roles = await defaults.setDefaultRoles(model.data.roles);
      sendMessage(localizedText(msg("screens.default_roles_saved")), "success");
      return;
    } catch (e) {
      error(e);
    }
  }
}
