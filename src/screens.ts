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
import { failure, permission, role, roleName } from "../types/auth.ts";
import * as admin from "./admin.ts";

const automatic = field(z.boolean(), {
  label: "Automatic",
  description:
    "Granted because this role name matches the username; remove the role to remove this automatic assignment.",
});
const roleRow = z.object({ role: roleName, automatic, explicit: z.boolean() });
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
    roles: role.pick({ name: true, description: true }).array(),
  });
  const model = new Model<z.infer<typeof schema>>({ roles: [] });
  while (true) {
    model.data.roles = await admin.listRoles();
    const event = await callScreen({
      id: "auth-roles",
      title: "Roles",
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-roles",
        root: {
          type: "list",
          bind: "roles",
          key: "name",
          display: ["name", "description"],
        },
      },
      header: {
        actions: [{ id: "add", label: "Create role", kind: "primary" }, {
          id: "failures",
          label: "Failed checks",
        }, { id: "refresh", label: "Refresh" }],
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
    } catch (e) {
      error(e);
    }
  }
}

async function editRole(
  existing?: z.infer<typeof role>,
): Promise<string | undefined> {
  const schema = role.pick({ name: true, description: true });
  const model = new Model({
    name: existing?.name,
    description: existing?.description ?? "",
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
      }],
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

async function roleDetail(name: string): Promise<void> {
  const schema = role.pick({ name: true, description: true }).extend({
    entries: permission.array(),
  });
  const model = new Model<z.infer<typeof schema>>({
    name,
    description: "",
    entries: [],
  });
  while (true) {
    const record = await admin.getRole(name);
    model.data.description = record.description;
    model.data.entries = Object.entries(record.permissions).map((
      [action, values],
    ) => ({ action, values }));
    const event = await callScreen({
      id: "auth-role",
      title: `Role ${name}`,
      schema,
      model,
      controls: [{ bind: "name", readOnly: true }, {
        bind: "description",
        readOnly: true,
        length: "long",
      }],
      layout: {
        schema: 1,
        id: "auth-role",
        root: {
          type: "stack",
          children: [
            { type: "detail", controls: ["name", "description"] },
            {
              type: "list",
              title: "Permissions",
              bind: "entries",
              key: "action",
              display: ["action", "values"],
            },
          ],
        },
      },
      header: {
        actions: [
          { id: "permission", label: "Add permission", kind: "primary" },
          { id: "included", label: "Included roles" },
          { id: "users", label: "Users" },
          { id: "edit", label: "Edit role" },
          { id: "delete", label: "Delete role", kind: "danger" },
          { id: "refresh", label: "Refresh" },
        ],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "permission") {
        await presentModal(() => editPermission(name));
      }
      if (event.action === "select" && typeof event.value === "string") {
        const entry = model.data.entries.find((row) =>
          row.action === event.value
        );
        if (entry) await presentModal(() => editPermission(name, entry));
      }
      if (event.action === "edit") await presentModal(() => editRole(record));
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
  existing?: z.infer<typeof permission>,
): Promise<void> {
  const model = new Model<Partial<z.infer<typeof permission>>>(
    existing ? { ...existing } : {},
  );
  while (true) {
    const event = await callScreen({
      id: "auth-permission",
      title: `Permission · ${name}`,
      schema: permission.partial(),
      model,
      controls: [{ bind: "action", readOnly: !!existing, length: "long" }, {
        bind: "values",
        length: "long",
      }],
      header: {
        actions: [
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
        const data = permission.parse(model.data);
        await admin.setPermission(name, data.action, data.values);
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
          type: "list",
          bind: "roles",
          key: "included",
          display: ["included"],
        },
      },
      header: {
        actions: [{ id: "add", label: "Include role", kind: "primary" }, {
          id: "refresh",
          label: "Refresh",
        }],
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
  while (true) {
    model.data.roles = await admin.userRoles(name);
    const event = await callScreen({
      id: "auth-user-roles",
      title: `Roles for ${name}`,
      schema,
      model,
      layout: {
        schema: 1,
        id: "auth-user-roles",
        root: {
          type: "list",
          bind: "roles",
          key: "role",
          display: ["role", "automatic"],
        },
      },
      header: {
        actions: [
          { id: "add", label: "Assign role", kind: "primary" },
          { id: "personal", label: "Personal permissions" },
          { id: "user", label: "Open user" },
          { id: "failures", label: "Failed checks" },
          { id: "refresh", label: "Refresh" },
        ],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "add") {
        const role = await presentModal(() => pick("Assign role", roleName));
        if (role) await admin.assignRole(name, role);
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
          type: "list",
          bind: "users",
          key: "username",
          display: ["username", "automatic"],
        },
      },
      header: {
        actions: [{ id: "add", label: "Assign user", kind: "primary" }, {
          id: "refresh",
          label: "Refresh",
        }],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "add") {
        const user = await presentModal(() => pick("Assign user", username));
        if (user) await admin.assignRole(user, name);
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
          type: "list",
          bind: "failures",
          key: "id",
          display: ["checkedAt", "username", "action", "value", "reason"],
        },
      },
      header: {
        actions: [
          { id: "refresh", label: "Refresh" },
          ...(offset ? [{ id: "previous", label: "Previous 100" }] : []),
          ...(model.data.failures.length === 100
            ? [{ id: "next", label: "Next 100" }]
            : []),
        ],
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
