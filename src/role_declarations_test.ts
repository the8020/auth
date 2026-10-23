import { assert, assertEquals, assertRejects, assertThrows } from "@std/assert";
import { authDatabase } from "./test_support.ts";

const DECLARATION = `
["dlis.einvoice.viewer"]
description = "View documents in your channels."
permissions = { "dlis.einvoice.documents.view" = { attribute = "dlis.einvoice.channel" } }

["dlis.einvoice.approver"]
description = "Approve documents in your channels."
permissions = { "dlis.einvoice.documents.approve" = { attribute = "dlis.einvoice.channel" } }

["dlis.einvoice.user"]
description = "eInvoice channel user."
collection = true
includes = ["dlis.einvoice.viewer", "dlis.einvoice.approver"]
`;

Deno.test("role declarations require the package prefix and known keys", async () => {
  const fixture = await authDatabase();
  const { parseRoleDeclarations } = await import("./role_declarations.ts");
  try {
    const roles = parseRoleDeclarations(DECLARATION, "dlis/einvoice");
    assertEquals(roles.map((item) => [item.name, item.collection]), [
      ["dlis.einvoice.viewer", false],
      ["dlis.einvoice.approver", false],
      ["dlis.einvoice.user", true],
    ]);
    assertEquals(roles[2]!.includes, [
      "dlis.einvoice.viewer",
      "dlis.einvoice.approver",
    ]);
    for (
      const [text, message] of [
        [
          '["acme.other.role"]\ndescription = "x"\n',
          "must start with dlis.einvoice.",
        ],
        ['["dlis.einvoice.x"]\ncolour = "red"\n', "unknown key colour"],
        ['["dlis.einvoice.x"]\nincludes = "y"\n', "includes must be"],
        ['["dlis.einvoice.x"]\ncollection = "yes"\n', "collection must be"],
      ] as const
    ) {
      assertThrows(
        () => parseRoleDeclarations(text, "dlis/einvoice"),
        TypeError,
        message,
      );
    }
  } finally {
    fixture.close();
  }
});

Deno.test("indexing synchronizes managed roles and protects them from edits", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  const { indexRoles } = await import("./role_declarations.ts");
  const { verify } = await import("../mod.ts");
  const root = await Deno.makeTempDir({ prefix: "the8020-auth-roles-" });
  const write = (text: string) =>
    Deno.mkdir(`${root}/dlis/einvoice/declarations`, { recursive: true })
      .then(() =>
        Deno.writeTextFile(
          `${root}/dlis/einvoice/declarations/auth-roles.toml`,
          text,
        )
      );
  const index = async (commit: string, active = true) => {
    const state = { packages: {} as Record<string, { error?: string }> };
    await indexRoles(state, {
      packages: [{
        package_id: "dlis/einvoice",
        package_commit: commit,
        active,
      }],
    }, new URL(`file://${root}/`));
    return state.packages["dlis/einvoice"]?.error;
  };
  try {
    await users.add("novak");
    await write(DECLARATION);
    assertEquals(await index("c1"), undefined);
    const user = await admin.getRole("dlis.einvoice.user");
    assertEquals(
      [user.managed, user.managedCommit, user.collection],
      ["dlis/einvoice", "c1", true],
    );
    assertEquals(
      (await admin.includedRoles("dlis.einvoice.user")).map((row) =>
        row.included
      ),
      ["dlis.einvoice.approver", "dlis.einvoice.viewer"],
    );
    await admin.assignRole("novak", "dlis.einvoice.user", true, {
      "dlis.einvoice.channel": "SK",
    });
    assertEquals(
      await verify("novak", "dlis.einvoice.documents.approve", "SK"),
      true,
    );

    // Managed roles change only through their declaration.
    for (
      const edit of [
        () => admin.setPermission("dlis.einvoice.viewer", "x.y", "*"),
        () =>
          admin.saveRole({
            name: "dlis.einvoice.viewer",
            description: "changed",
            permissions: {},
          }),
        () => admin.deleteRole("dlis.einvoice.viewer"),
        () => admin.includeRole("dlis.einvoice.viewer", "dlis.einvoice.user"),
      ]
    ) await assertRejects(edit, Error, "managed by dlis/einvoice");
    // They can still be included in a custom collection.
    await admin.createRole({
      name: "team",
      description: "",
      permissions: {},
      collection: true,
    });
    await admin.includeRole("team", "dlis.einvoice.viewer");

    // A hand-made role with a declared name is never taken over.
    await admin.createRole({
      name: "dlis.einvoice.manual",
      description: "mine",
      permissions: { "a.b": "*" },
    });
    await write(
      DECLARATION +
        '\n["dlis.einvoice.manual"]\ndescription = "theirs"\n',
    );
    assert((await index("c2"))?.includes("not managed by dlis/einvoice"));
    assertEquals(
      (await admin.getRole("dlis.einvoice.manual")).description,
      "mine",
    );

    // Removed roles in use become obsolete; unused ones are deleted.
    await write(
      '["dlis.einvoice.user"]\ndescription = "u"\ncollection = true\nincludes = ["dlis.einvoice.viewer"]\n',
    );
    // The viewer is no longer declared but still included, so it stays.
    assertEquals(await index("c3"), undefined);
    const viewer = await admin.getRole("dlis.einvoice.viewer");
    assertEquals(viewer.obsolete, true);
    await assertRejects(() => admin.getRole("dlis.einvoice.approver"));
    assertEquals(
      await verify("novak", "dlis.einvoice.documents.approve", "SK"),
      false,
    );

    // A removed package leaves only roles still in use.
    assertEquals(await index("c4", false), undefined);
    assertEquals((await admin.getRole("dlis.einvoice.user")).obsolete, true);
  } finally {
    fixture.close();
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("copies of managed roles record their origin and adopt template changes", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const { synchronize } = await import("./role_declarations.ts");
  const { command } = await import("./commands.ts");
  try {
    const declare = (permissions: Record<string, string>, includes: string[]) =>
      synchronize("dlis/einvoice", "c1", [{
        name: "dlis.einvoice.viewer",
        description: "View",
        permissions,
        collection: false,
        includes: [],
      }, {
        name: "dlis.einvoice.base",
        description: "Base",
        permissions: {},
        collection: true,
        includes,
      }], []);
    await declare({ "dlis.einvoice.documents.view": "*" }, [
      "dlis.einvoice.viewer",
    ]);
    const copy = await admin.copyRole("dlis.einvoice.base", "my-base");
    assertEquals(copy.managed, null);
    assertEquals(copy.copiedFrom, {
      role: "dlis.einvoice.base",
      package: "dlis/einvoice",
      commit: "c1",
    });
    // A copy is an ordinary role: it can lose what the template grants.
    await admin.setPermission("my-base", "dlis.einvoice.extra", "SK");
    assertEquals((await admin.templateChanges("my-base")).changes, [{
      kind: "permission",
      key: "dlis.einvoice.extra",
      change: "removed",
      copy: '"SK"',
    }]);
    await admin.includeRole("dlis.einvoice.base", "dlis.einvoice.viewer")
      .catch(() => {});
    await declare({}, []);
    const changed = await command("changes", ["my-base"]) as {
      changes: { key: string; change: string }[];
    };
    assertEquals(
      changed.changes.map((item) => [item.key, item.change]),
      [["dlis.einvoice.extra", "removed"], ["dlis.einvoice.viewer", "removed"]],
    );
    await command("adopt", ["my-base"]);
    assertEquals((await admin.getRole("my-base")).permissions, {});
    assertEquals(await admin.includedRoles("my-base"), []);
    assertEquals((await admin.templateChanges("my-base")).changes, []);
    await assertRejects(() => admin.copyRole("dlis.einvoice.base", "my-base"));
    await assertRejects(() => admin.adoptTemplate("dlis.einvoice.viewer"));
  } finally {
    fixture.close();
  }
});

Deno.test("platform action keys migrate to the the8020 namespace once", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const { migratePlatformActions, namespacedAction } = await import(
    "./migrations.ts"
  );
  try {
    assertEquals(
      namespacedAction("users.user.edit"),
      "the8020.users.user.edit",
    );
    assertEquals(namespacedAction("users.*"), "the8020.users.*");
    assertEquals(namespacedAction("*"), "*");
    assertEquals(namespacedAction("dlis.einvoice.view"), "dlis.einvoice.view");
    assertEquals(
      namespacedAction("the8020.users.user.edit"),
      "the8020.users.user.edit",
    );
    await admin.createRole({
      name: "old",
      description: "",
      permissions: {
        "users.user.edit": "alice",
        "packages.*": "*",
        "*": "x",
        "sales.customer.view": "7522",
        "auth.roles.view": "a",
        "the8020.auth.roles.view": "b",
      },
    });
    assertEquals(await migratePlatformActions(), { roles: 1 });
    assertEquals((await admin.getRole("old")).permissions, {
      "*": "x",
      "sales.customer.view": "7522",
      "the8020.auth.roles.view": "b",
      "the8020.users.user.edit": "alice",
      "the8020.packages.*": "*",
    });
    assertEquals(await migratePlatformActions(), { roles: 0 });
  } finally {
    fixture.close();
  }
});

Deno.test("the users package's platform role declarations parse", async () => {
  const fixture = await authDatabase();
  const { parseRoleDeclarations } = await import("./role_declarations.ts");
  try {
    const roles = parseRoleDeclarations(
      await Deno.readTextFile(
        new URL("../../users/declarations/auth-roles.toml", import.meta.url),
      ),
      "the8020/users",
    );
    assertEquals(roles.map((role) => [role.name, role.permissions]), [
      ["the8020.users.administrator", { "*": "*" }],
      ["the8020.users.user", {}],
    ]);
  } finally {
    fixture.close();
  }
});

Deno.test("new users receive the configured default roles once", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  const defaults = await import("./defaults.ts");
  const { command } = await import("./commands.ts");
  const assigned = async (name: string) =>
    (await admin.userRoles(name)).filter((row) => row.explicit).map((row) =>
      row.role
    );
  try {
    await admin.createRole({
      name: "the8020.users.user",
      description: "",
      permissions: {},
      collection: true,
    });
    await admin.createRole({ name: "staff", description: "", permissions: {} });
    await users.add("novak");
    // Creating an account publishes users.created for the listener.
    assert(
      fixture.calls.some((call) =>
        call.operation === "event.emit" && call.input.name === "users.created"
      ),
    );
    assertEquals(await command("defaults", []), {
      roles: ["the8020.users.user"],
    });
    assertEquals(await defaults.assignDefaultRoles("novak"), [
      "the8020.users.user",
    ]);
    assertEquals(await assigned("novak"), ["the8020.users.user"]);

    assertEquals(await command("defaults", ["staff", "the8020.users.user"]), {
      roles: ["staff", "the8020.users.user"],
    });
    await assertRejects(
      () => command("defaults", ["missing"]),
      Error,
      "missing",
    );
    await users.add("svoboda");
    await defaults.assignDefaultRoles("svoboda");
    assertEquals(await assigned("svoboda"), ["staff", "the8020.users.user"]);

    // A replayed event for an old account assigns nothing.
    const later = new Date(Date.now() + 2 * 60 * 60_000);
    await users.add("dvorak");
    assertEquals(await defaults.assignDefaultRoles("dvorak", later), []);
    assertEquals(await defaults.assignDefaultRoles("nobody"), []);

    assertEquals(await command("defaults", ["--none"]), { roles: [] });
    await users.add("cerny");
    assertEquals(await defaults.assignDefaultRoles("cerny"), []);

    fixture.asUser("novak");
    await assertRejects(() => defaults.setDefaultRoles([]));
  } finally {
    fixture.close();
  }
});

Deno.test("action declarations may mark actions checked without a value", async () => {
  const { parseActionDeclarations } = await import("./declarations.ts");
  assertEquals(
    parseActionDeclarations(
      `"a.b.sql.execute" = { description = "Run SQL; value is empty.", value = false }
"a.b.table.view" = "View a table; value is the table ID."
`,
    ),
    [
      {
        action: "a.b.sql.execute",
        description: "Run SQL; value is empty.",
        value: false,
      },
      {
        action: "a.b.table.view",
        description: "View a table; value is the table ID.",
      },
    ],
  );
  assertThrows(
    () =>
      parseActionDeclarations(`"a.b.c" = { description = "x", value = true }`),
    TypeError,
    "value may only be false",
  );
  // Every platform declaration still parses.
  for await (const entry of Deno.readDir(new URL("../../", import.meta.url))) {
    if (!entry.isDirectory) continue;
    const file = new URL(
      `../../${entry.name}/declarations/auth.toml`,
      import.meta.url,
    );
    try {
      parseActionDeclarations(await Deno.readTextFile(file));
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
  }
});
