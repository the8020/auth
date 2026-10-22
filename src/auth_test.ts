import { assert, assertEquals, assertRejects, assertThrows } from "@std/assert";
import { expression, pattern } from "./matching.ts";
import { authDatabase } from "./test_support.ts";

/** `users.add` publishes users.created; these checks count other calls. */
const created = (call: { operation: string; input: Record<string, unknown> }) =>
  call.operation === "event.emit" && call.input.name === "users.created";

Deno.test("patterns and inclusive ranges keep exclusions local and values exact", () => {
  const match = expression("7000-9000,25*,4444,3333,!8000-8200,!2577");
  for (
    const value of [
      "7000",
      "7522",
      "7999",
      "8201",
      "9000",
      "2500",
      "25abc",
      "4444",
      "3333",
    ]
  ) assertEquals(match(value), "allowed", value);
  for (const value of ["8000", "8100", "8200", "2577"]) {
    assertEquals(match(value), "excluded", value);
  }
  for (const value of ["6999", "9001", "92577", ""]) {
    assertEquals(match(value), "no_value_match", value);
  }
  assertEquals(expression("A-Z,!M-P")("B"), "allowed");
  assertEquals(expression("A-Z,!M-P")("N"), "excluded");
  assertEquals(expression("A-Z")("b"), "no_value_match");
  assertEquals(expression("9-11")("10"), "allowed");
  assertEquals(
    expression("9007199254740993-9007199254740995")("9007199254740992"),
    "no_value_match",
  );
  assertEquals(expression("-1.5-0.25")("-0.05"), "allowed");
  assertEquals(expression("-1.5-0.25")("0.251"), "no_value_match");
  assertEquals(expression("-2")("-2"), "allowed");
  assertEquals(expression("!forbidden")("other"), "no_value_match");
  assertEquals(expression("*")(""), "allowed");
  assertEquals(
    expression(String.raw`a\,b,foo\-bar,\!yes,\*,a\\b`)("a,b"),
    "allowed",
  );
  assertEquals(expression(String.raw`foo\-bar`)("foo-bar"), "allowed");
  assertEquals(expression(String.raw`\*`)("anything"), "no_value_match");
  assert(pattern("sales.customer.*")("sales.customer.edit"));
  assert(!pattern("sales.customer.*")("prefix.sales.customer.edit"));
  assert(!pattern("sales.customer.*")("salesXcustomer.edit"));
  assert(pattern("a?c")("a😄c"));
  assert(!pattern("a*b*c")("ab".repeat(1000)));
  for (const value of ["", "!", "a,", "9-1", "Z-A", "a-b-c", "abc\\"]) {
    assertThrows(() => expression(value), TypeError, undefined, value);
  }
});

Deno.test("real role operations, trusted checks, denials and mutation boundaries", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  const { default: userDeleted } = await import(
    "../programs/user-deleted/program.ts"
  );
  const { check, requirePermission, AuthorizationError } = await import(
    "../mod.ts"
  );
  const { command } = await import("./commands.ts");
  const Failures = (await import("../tables/failures.ts")).default;
  try {
    await users.add("alice");
    await users.add("bob");
    assertEquals(await admin.listRoles(), []);
    fixture.asUser("alice");
    assertEquals(await check("sales.customer.edit", "7522"), false);
    const failed = (await Failures.selectAll().execute())[0]!;
    assertEquals(
      [failed.username, failed.action, failed.value, failed.reason],
      ["alice", "sales.customer.edit", "7522", "no_roles"],
    );
    assert(failed.checkedAt instanceof Date);
    assertEquals(failed.details, [{ role: "alice", reason: "missing_role" }]);
    await assertRejects(
      () =>
        admin.createRole({
          name: "alice",
          description: "",
          permissions: { "*": "*" },
        }),
      AuthorizationError,
    );
    await assertRejects(() => users.add("carol"), AuthorizationError);
    const { packages } = await import("/p/the8020/packages/src/admin.ts");
    await assertRejects(
      () => packages.delete("acme/example", true),
      AuthorizationError,
    );
    const services = await import("/p/the8020/services/src/admin.ts");
    await assertRejects(
      () => services.updateDesired("acme/example/api", { enabled: false }),
      AuthorizationError,
    );
    await assertRejects(
      () => services.restart("acme/example/api"),
      AuthorizationError,
    );
    assertEquals(fixture.calls.filter((call) => !created(call)), []);
    fixture.asUser("system");
    await command("create", [
      "sales",
      "--permissions",
      JSON.stringify({
        "sales.customer.*": "7000-9000,25*,4444,3333,!8000-8200,!2577",
      }),
    ]);
    await command("create", ["team"]);
    await command("include", ["team", "sales"]);
    await command("include", ["sales", "team"]);
    await command("assign", ["alice", "team"]);
    await command("assign", ["alice", "team"]);
    fixture.asUser("alice");
    assertEquals(await check("sales.customer.edit", "7522"), true);
    assertEquals(await check("sales.customer.edit", "8100"), false);
    assertEquals(await check("other", "7522"), false);
    fixture.asUser("system");
    await admin.personalRole("alice");
    await admin.setPermission("alice", "sales.customer.edit", "8100");
    await admin.setPermission(
      "alice",
      "the8020.services.service.restart",
      "acme/example/api",
    );
    await admin.setPermission(
      "alice",
      "the8020.packages.package.delete",
      "acme/example",
    );
    assertEquals(
      (await admin.userRoles("alice")).map((row) => [row.role, row.automatic]),
      [["alice", true], ["team", false]],
    );
    assertEquals((await admin.roleUsers("alice"))[0]?.automatic, true);
    fixture.asUser("alice");
    assert(await check("sales.customer.edit", "8100"));
    await services.restart("acme/example/api");
    await packages.delete("acme/example", true);
    assertEquals(
      fixture.calls.filter((call) => !created(call)).map((call) =>
        call.operation
      ),
      [
        "service.restart",
        "package.delete",
      ],
    );
    fixture.asUser("system");
    await admin.setPermission("alice", "sales.customer.edit");
    fixture.asUser("alice");
    await assertRejects(
      () => requirePermission("sales.customer.edit", "8100"),
      AuthorizationError,
    );
    fixture.asUser("system");
    await admin.setPermission("sales", "sales.customer.edit", "8100");
    fixture.asUser("alice");
    assert(await check("sales.customer.edit", "8100"));
    fixture.asUser("system");
    await admin.assignRole("bob", "team");
    await admin.assignRole("bob", "team", false);
    await admin.assignRole("bob", "alice");
    await admin.includeRole("team", "alice");
    await admin.includeRole("alice", "team");
    await users.remove("alice");
    await assertRejects(() => users.user("alice"));
    // The publisher deletes only its own data. Auth cleanup belongs to the listener.
    assertEquals((await admin.getRole("alice")).name, "alice");
    assertEquals((await admin.userRoles("bob"))[0]?.role, "alice");
    const deleted = fixture.calls.find((call) =>
      call.operation === "event.emit" && !created(call)
    )!
      .input;
    assertEquals(deleted, {
      name: "users.deleted",
      data: { username: "alice" },
    });
    await assertRejects(() =>
      userDeleted({ name: "users.deleted", data: {} })
    );
    await userDeleted(deleted);
    await userDeleted(deleted);
    assertEquals((await admin.roleUsers("team")).length, 0);
    await assertRejects(() => admin.getRole("alice"));
    assertEquals(await admin.userRoles("bob"), []);
    assertEquals(await admin.includedRoles("team"), [{
      role: "team",
      included: "sales",
    }]);
    await users.add("alice");
    fixture.asUser("alice");
    assertEquals(await check("sales.customer.edit", "7522"), false);
    fixture.asUser("system");
    await users.remove("bob");
    assertEquals(
      fixture.calls.filter((call) =>
        call.operation === "event.emit" && !created(call)
      ).map((
        call,
      ) => call.input),
      [
        { name: "users.deleted", data: { username: "alice" } },
        { name: "users.deleted", data: { username: "bob" } },
      ],
    );
    await admin.createRole({
      name: "nobody",
      description: "",
      permissions: {},
    });
    await assertRejects(() => users.remove("nobody"));
    assertEquals((await admin.getRole("nobody")).name, "nobody");
    assertEquals(
      fixture.calls.filter((call) =>
        call.operation === "event.emit" && !created(call)
      ).length,
      2,
    );
    await admin.deleteRole("sales");
    assertEquals(await admin.includedRoles("team"), []);
    await assertRejects(() => admin.assignRole("nobody", "team"));
    await assertRejects(() =>
      command("create", ["bad", "--permissions", "[]"])
    );
    const count = (await Failures.selectAll().execute()).length;
    assert(await check("anything", "anything"));
    assertEquals((await Failures.selectAll().execute()).length, count);
    fixture.asUser("ghost");
    fixture.database.exec("DROP TABLE the8020__auth__failures");
    await assertRejects(() => check("anything", "anything"));
  } finally {
    fixture.close();
  }
});

Deno.test({
  name: "declarations scan installed namespaces and sort advisory keys",
  permissions: { read: true, write: true },
  async fn() {
    const { attributeDeclarations, declarations } = await import(
      "./declarations.ts"
    );
    const root = await Deno.makeTempDir();
    try {
      await Deno.mkdir(`${root}/acme/one/declarations`, { recursive: true });
      await Deno.mkdir(`${root}/acme/two`, { recursive: true });
      await Deno.writeTextFile(
        `${root}/acme/one/declarations/auth.toml`,
        '"sales.z.edit" = "Edit Z"\n"sales.a.view" = "View A"\n',
      );
      assertEquals(await declarations(new URL(`file://${root}/`)), [{
        action: "sales.a.view",
        description: "View A",
      }, { action: "sales.z.edit", description: "Edit Z" }]);
      await Deno.writeTextFile(
        `${root}/acme/one/declarations/auth-attributes.toml`,
        '"sales.region" = "Sales region code"\n',
      );
      assertEquals(
        await attributeDeclarations(new URL(`file://${root}/`)),
        [{ attribute: "sales.region", description: "Sales region code" }],
      );
    } finally {
      await Deno.remove(root, { recursive: true });
    }
  },
});
