import {
  BACK_EVENT,
  callScreen,
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

const automatic = field(z.boolean(), {
  label: "Automatic",
  description:
    "Granted because this role name matches the username; remove the role to remove this automatic assignment.",
});
const roleRow = z.object({ role: roleName, automatic, explicit: z.boolean() });
/** An entry takes its values either from the expression or from an attribute. */
const permissionEntry = permission.extend({
  values: permission.shape.values.optional(),
  attribute: field(attributeName.optional(), {
    label: "Attribute",
    description:
      "Take the allowed values from this attribute of each assignment instead of Allowed values.",
  }),
});
const attributeRow = z.object({
  attribute: attributeName,
  values: permission.shape.values.optional(),
  comparisons: permission.shape.comparisons,
});
const userRow = z.object({ username, automatic, explicit: z.boolean() });
function error(value: unknown) {
  sendMessage(value instanceof Error ? value.message : String(value), "error");
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
      header: { actions: [{ id: "save", label: "Add", kind: "primary" }] },
    });
    if (event.action === BACK_EVENT) return;
    if (event.action === "save" && model.data.value) return model.data.value;
  }
}

async function confirm(title: string): Promise<boolean> {
  return await presentModal(async () =>
    (await callScreen({
      id: "auth-confirm",
      title,
      schema: z.object({}),
      model: new Model({}),
      header: { actions: [{ id: "delete", label: "Delete", kind: "danger" }] },
    })).action === "delete"
  );
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
    model.data.roles = (await admin.listRoles()).map((row) => ({
      ...row,
      managed: row.managed ?? "",
    }));
    const event = await callScreen({
      id: "auth-roles",
      title: "Roles",
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-roles",
        root: {
          toolbar: [{ id: "add", label: "Create role", kind: "primary" }, {
            id: "refresh",
            label: "Refresh",
          }],
          type: "list",
          bind: "roles",
          key: "name",
          display: ["name", "description", "managed", "collection", "obsolete"],
          columnOptions: { description: { length: "long" } },
        },
      },
      header: {
        actions: [{ id: "audit", label: "Audit" }, {
          id: "failures",
          label: "Failed checks",
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
      title: existing ? "Edit role" : "Create role",
      schema: schema.partial({ name: true }),
      model,
      controls: [{ bind: "name", readOnly: !!existing, length: "long" }, {
        bind: "description",
        length: "long",
      }, { bind: "collection" }],
      header: {
        actions: [{ id: "save", label: "Save role", kind: "primary" }],
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
      error(e);
    }
  }
}

const templateChange = z.object({
  key: field(z.string(), {
    label: "Action or role",
    description: "The permission action or included role that differs.",
  }),
  kind: field(z.string(), {
    label: "Kind",
    description: "Whether a permission or an included role differs.",
  }),
  change: field(z.string(), {
    label: "Change",
    description:
      "Added or removed in the template since the copy, or changed values.",
  }),
  template: field(z.string(), {
    label: "Template",
    description: "The template's current values.",
  }),
  copy: field(z.string(), {
    label: "This copy",
    description: "This role's values.",
  }),
});

async function roleDetail(name: string): Promise<void> {
  const schema = role.pick({ name: true, description: true }).extend({
    managed: roleOrigin.managed,
    collection: roleOrigin.collection,
    obsolete: roleOrigin.obsolete,
    copiedFrom: field(z.string(), {
      label: "Copied from",
      description: "The package role and commit this role was copied from.",
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
    model.data.description = record.description;
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
      isAttributeReference(values)
        ? { action, attribute: values.attribute, comparisons: false }
        : {
          action,
          values: typeof values === "string" ? values : values.comparisons,
          comparisons: typeof values !== "string",
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
      title: `Role ${name}`,
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
                label: "Add permission",
                kind: "primary",
              }],
              type: "list",
              title: "Permissions",
              bind: "entries",
              key: "action",
              display: ["action", "values", "comparisons", "attribute"],
            },
            ...(record.copiedFrom
              ? [{
                toolbar: model.data.changes.length
                  ? [{
                    id: "adopt",
                    label: "Adopt template changes",
                    kind: "primary" as const,
                  }]
                  : [],
                type: "list",
                title: "Changes in the template",
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
          { id: "included", label: "Included roles" },
          { id: "users", label: "Users" },
          { id: "copy", label: "Copy role" },
          ...(managed ? [] : [
            { id: "edit", label: "Edit role" },
            { id: "delete", label: "Delete role", kind: "danger" as const },
          ]),
          { id: "refresh", label: "Refresh" },
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
        const target = await presentModal(() => pick("Copy as", roleName));
        if (target) {
          await admin.copyRole(name, target);
          await presentPage(() => roleDetail(target));
        }
      }
      if (
        event.action === "adopt" &&
        await confirm(`Replace ${name}'s permissions with its template's?`)
      ) await admin.adoptTemplate(name);
      if (event.action === "included") {
        await presentPage(() => includedRoles(name));
      }
      if (event.action === "users") await presentPage(() => roleUsers(name));
      if (
        event.action === "delete" &&
        await confirm(`Delete role ${name} and all its assignments?`)
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
    existing ? { ...existing } : { comparisons: false },
  );
  while (true) {
    const event = await callScreen({
      id: "auth-permission",
      title: `Permission · ${name}`,
      schema: permissionEntry.partial(),
      model,
      controls: [
        { bind: "action", readOnly: !!existing, length: "long" },
        { bind: "values", readOnly: managed, length: "long" },
        { bind: "comparisons", readOnly: managed },
        { bind: "attribute", readOnly: managed, length: "long" },
      ],
      header: {
        actions: managed ? [] : [
          { id: "save", label: "Save permission", kind: "primary" },
          ...(existing
            ? [{
              id: "delete",
              label: "Delete permission",
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
        if (!data.attribute && !data.values) {
          throw new TypeError("Enter Allowed values or an Attribute");
        }
        await admin.setPermission(
          name,
          data.action,
          data.attribute
            ? { attribute: data.attribute }
            : data.comparisons
            ? { comparisons: data.values! }
            : data.values!,
        );
        return;
      }
      if (
        existing && event.action === "delete" &&
        await confirm(`Delete permission ${existing.action}?`)
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
      title: `Included roles · ${name}`,
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-includes",
        root: {
          toolbar: [{ id: "add", label: "Include role", kind: "primary" }, {
            id: "refresh",
            label: "Refresh",
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
          pick("Include role", roleName)
        );
        if (included) await admin.includeRole(name, included);
      }
      if (event.action === "select" && typeof event.value === "string") {
        const included = event.value;
        await presentModal(async () => {
          const selected = await callScreen({
            id: "auth-included",
            title: `Included role ${included}`,
            schema: z.object({ role: roleName }),
            model: new Model({ role: included }),
            controls: [{ bind: "role", readOnly: true }],
            header: {
              actions: [{ id: "open", label: "Open role" }, {
                id: "remove",
                label: "Remove inclusion",
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
      title: `Roles for ${name}`,
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-user-roles",
        root: {
          toolbar: [{ id: "add", label: "Assign role", kind: "primary" }, {
            id: "personal",
            label: "Personal permissions",
          }, { id: "refresh", label: "Refresh" }],
          type: "list",
          bind: "roles",
          key: "role",
          display: ["role", "automatic"],
        },
      },
      header: {
        actions: [{ id: "user", label: "Open user" }, {
          id: "failures",
          label: "Failed checks",
        }],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "add") {
        const role = await presentModal(() => pick("Assign role", roleName));
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
            title: `${name} · ${row.role}`,
            schema: roleRow,
            model: new Model(row),
            controls: [{ bind: "role", readOnly: true }, {
              bind: "automatic",
              readOnly: true,
            }],
            header: {
              actions: [
                { id: "open", label: "Open role" },
                ...(row.explicit
                  ? [{ id: "attributes", label: "Attribute values" }]
                  : []),
                ...(row.explicit
                  ? [{
                    id: "remove",
                    label: "Remove assignment",
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
        comparisons: values !== undefined && typeof values !== "string",
      };
    }),
  });
  while (true) {
    const event = await callScreen({
      id: "auth-assignment-attributes",
      title: `${username} · ${roleName} · attribute values`,
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-assignment-attributes",
        root: {
          type: "list",
          bind: "attributes",
          key: "attribute",
          display: ["attribute", "values", "comparisons"],
        },
      },
      header: {
        actions: [{
          id: "save",
          label: "Save attribute values",
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
              title: `${roleName} · ${row.attribute}`,
              schema: attributeRow,
              model: edited,
              controls: [
                { bind: "attribute", readOnly: true, length: "long" },
                {
                  bind: "values",
                  length: "long",
                },
                { bind: "comparisons" },
              ],
              header: {
                actions: [{ id: "done", label: "Done", kind: "primary" }],
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
          attributes[row.attribute] = row.comparisons
            ? { comparisons: row.values }
            : row.values;
        }
        await admin.assignRole(username, roleName, true, attributes);
        sendMessage("Attribute values saved", "success");
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
      title: `Users with ${name}`,
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-role-users",
        root: {
          toolbar: [{ id: "add", label: "Assign user", kind: "primary" }, {
            id: "refresh",
            label: "Refresh",
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
        const user = await presentModal(() => pick("Assign user", username));
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
            title: `${name} · ${row.username}`,
            schema: userRow,
            model: new Model(row),
            controls: [{ bind: "username", readOnly: true }, {
              bind: "automatic",
              readOnly: true,
            }],
            header: {
              actions: [
                { id: "open", label: "Open user" },
                { id: "roles", label: "User roles" },
                ...(row.explicit
                  ? [{ id: "attributes", label: "Attribute values" }]
                  : []),
                ...(row.explicit
                  ? [{
                    id: "remove",
                    label: "Remove assignment",
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
      title: name ? `Failed checks · ${name}` : "Failed authorization checks",
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-failures",
        root: {
          toolbar: [
            { id: "refresh", label: "Refresh" },
            ...(offset ? [{ id: "previous", label: "Previous 100" }] : []),
            ...(model.data.failures.length === 100
              ? [{ id: "next", label: "Next 100" }]
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
            label: "Details",
            control: "textarea",
            rowSpan: 8,
          }),
        });
        await callScreen({
          id: "auth-failure",
          title: "Failed check",
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
  label: "Keep records (days)",
  description:
    "Audited successes and failed checks older than this are removed every night.",
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
      title: name ? `Audit · ${name}` : "Authorization audit",
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
              { id: "refresh", label: "Refresh" },
              { id: "retention", label: "Change retention" },
              ...(offset ? [{ id: "previous", label: "Previous 100" }] : []),
              ...(model.data.grants.length === 100
                ? [{ id: "next", label: "Next 100" }]
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
            title: "Audit retention",
            schema: z.object({ days: retention }),
            model: edit,
            header: {
              actions: [{ id: "save", label: "Save", kind: "primary" }],
            },
          });
          if (result.action === BACK_EVENT) return;
          if (result.action !== "save") continue;
          try {
            await audit.setAuditRetention(edit.data.days);
            sendMessage(`Records are kept for ${edit.data.days} days`, "info");
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
        label: "Values",
        description: "Attribute values given with this assignment.",
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
      title: "My roles",
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-own-roles",
        root: {
          toolbar: [{ id: "refresh", label: "Refresh" }],
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
