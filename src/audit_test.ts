import { assert, assertEquals, assertRejects } from "@std/assert";
import { authDatabase } from "./test_support.ts";

Deno.test("only platform operations other than view are audited unless declared", async () => {
  const fixture = await authDatabase();
  const { audited } = await import("./declarations.ts");
  const { indexRoles } = await import("./role_declarations.ts");
  const root = await Deno.makeTempDir({ prefix: "the8020-auth-audit-" });
  try {
    await Deno.mkdir(`${root}/acme/sales/declarations`, { recursive: true });
    await Deno.writeTextFile(
      `${root}/acme/sales/declarations/auth.toml`,
      `"acme.sales.order.approve" = { description = "Approve; value is country.", audit = true }
"acme.sales.order.edit" = "Edit; value is country."
"acme.sales.order.list" = { description = "List; value is empty.", audit = false }
"acme.sales.secret.view" = { description = "Read; value is empty.", audit = true }
"the8020.users.user.edit" = { description = "Not ours.", audit = false }
`,
    );
    const index = async (active: boolean) => {
      const state = { packages: {} as Record<string, { error?: string }> };
      await indexRoles(state, {
        packages: [{ package_id: "acme/sales", package_commit: "c1", active }],
      }, new URL(`file://${root}/`));
      return state.packages["acme/sales"]?.error;
    };
    // Another package's action keeps the platform default.
    assertEquals(
      await index(true),
      "audit of the8020.users.user.edit must be declared by its package",
    );
    const cases: [string, boolean][] = [
      ["the8020.users.user.edit", true],
      ["the8020.users.user.view", false],
      ["acme.sales.order.edit", false],
      ["acme.sales.order.list", false],
      ["acme.sales.order.approve", true],
      ["acme.sales.secret.view", true],
      ["acme.other.thing.delete", false],
    ];
    for (const [action, expected] of cases) {
      assertEquals(await audited(action), expected, action);
    }
    // Removing the package removes its flags.
    assertEquals(await index(false), undefined);
    assertEquals(await audited("acme.sales.order.approve"), false);
  } finally {
    fixture.close();
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("audited successes record the granting role; view and denials do not", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  const { check } = await import("../mod.ts");
  const { grantedChecks } = await import("./audit.ts");
  try {
    await users.add("novak");
    await admin.createRole({
      name: "editor",
      description: "",
      permissions: {
        "the8020.test.item.edit": "A*",
        "the8020.test.item.view": "*",
      },
    });
    await admin.assignRole("novak", "editor");
    fixture.asUser("novak");
    assertEquals(await check("the8020.test.item.edit", "A1"), true);
    assertEquals(await check("the8020.test.item.view", "A1"), true);
    assertEquals(await check("the8020.test.item.edit", "B1"), false);
    // The system user bypasses checks and is never audited.
    fixture.asUser("system");
    assertEquals(await check("the8020.test.item.edit", "C1"), true);
    const grants = await grantedChecks();
    assertEquals(
      grants.map((row) => [row.username, row.action, row.value, row.role]),
      [["novak", "the8020.test.item.edit", "A1", "editor"]],
    );
    assertEquals((await admin.failedChecks("novak")).length, 1);

    // Reading the audit needs its own permission.
    fixture.asUser("novak");
    await assertRejects(
      () => grantedChecks(),
      Error,
      "the8020.auth.audit.view",
    );
  } finally {
    fixture.close();
  }
});

Deno.test("retention is configurable and cleanup removes expired records", async () => {
  const fixture = await authDatabase();
  const users = await import("/p/the8020/users/src/admin.ts");
  const audit = await import("./audit.ts");
  const { command } = await import("./commands.ts");
  try {
    await users.add("novak");
    assertEquals(await audit.auditRetention(), 30);
    assertEquals(await command("retention", ["7"]), { days: 7 });
    assertEquals(await command("retention", []), { days: 7 });
    await assertRejects(() => command("retention", ["0"]), Error, "1–3650");
    await assertRejects(() => command("retention", ["x"]), Error, "usage");

    const now = new Date("2026-10-21T03:00:00Z");
    const day = 86_400_000;
    for (const [id, age] of [["old", 8], ["new", 6]] as const) {
      const checkedAt = new Date(now.getTime() - age * day).toISOString();
      fixture.database.prepare(
        `insert into the8020__auth__grants (id, username, action, value, "checkedAt", role) values (?, 'novak', 'the8020.a.b.edit', '', ?, 'r')`,
      ).run(id, checkedAt);
      fixture.database.prepare(
        `insert into the8020__auth__failures (id, username, action, value, "checkedAt", reason, details) values (?, 'novak', 'the8020.a.b.edit', '', ?, 'no_roles', '[]')`,
      ).run(id, checkedAt);
    }
    assertEquals(await audit.cleanupAudit(now), {
      days: 7,
      grants: 1,
      failures: 1,
    });
    const left = fixture.database.prepare(
      "select id from the8020__auth__grants union all select id from the8020__auth__failures",
    ).all().map((row) => row.id);
    assertEquals(left, ["new", "new"]);

    fixture.asUser("novak");
    await assertRejects(() => audit.setAuditRetention(10));
    await assertRejects(() => audit.cleanupAudit(now));
  } finally {
    fixture.close();
  }
});

Deno.test("usersWithPermission lists enabled accounts granted the value", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  const { usersWithPermission } = await import("../mod.ts");
  try {
    for (const name of ["anna", "boris", "cyril", "dana"]) {
      await users.add(name);
    }
    await admin.createRole({
      name: "dlis.einvoice.approver",
      description: "",
      permissions: {
        "dlis.einvoice.documents.approve": {
          attribute: "dlis.einvoice.channel",
        },
      },
    });
    await admin.assignRole("anna", "dlis.einvoice.approver", true, {
      "dlis.einvoice.channel": "SK,CZ",
    });
    await admin.assignRole("boris", "dlis.einvoice.approver", true, {
      "dlis.einvoice.channel": "CZ",
    });
    await admin.assignRole("dana", "dlis.einvoice.approver", true, {
      "dlis.einvoice.channel": "SK",
    });
    fixture.database.exec(
      "update the8020__users__users set enabled = 0 where username = 'dana'",
    );
    assertEquals(
      await usersWithPermission("dlis.einvoice.documents.approve", "SK"),
      ["anna"],
    );
    assertEquals(
      await usersWithPermission("dlis.einvoice.documents.approve", "CZ"),
      ["anna", "boris"],
    );
    assert(
      (await usersWithPermission("dlis.einvoice.documents.approve", "DE"))
        .length === 0,
    );
    // It never audits.
    assertEquals((await admin.failedChecks()).length, 0);
  } finally {
    fixture.close();
  }
});
