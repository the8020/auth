import { assert, assertEquals, assertRejects } from "@std/assert";
import { authDatabase } from "./test_support.ts";

const CHANNEL = "dlis.einvoice.channel";
const VIEW = "dlis.einvoice.documents.view";
const APPROVE = "dlis.einvoice.documents.approve";

Deno.test("assignment attributes bind role entries through nesting and keep correlation", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  const { verify, filter, permitsAny, check } = await import("../mod.ts");
  try {
    for (const name of ["novak", "svoboda", "dvorak"]) await users.add(name);
    await admin.createRole({
      name: "dlis.einvoice.viewer",
      description: "",
      permissions: { [VIEW]: { attribute: CHANNEL } },
    });
    await admin.createRole({
      name: "dlis.einvoice.approver",
      description: "",
      permissions: { [APPROVE]: { attribute: CHANNEL } },
    });
    // A collection carries no entries; included roles inherit the binding.
    await admin.createRole({
      name: "dlis.einvoice.user",
      description: "",
      permissions: {},
    });
    await admin.includeRole("dlis.einvoice.user", "dlis.einvoice.viewer");
    await admin.includeRole("dlis.einvoice.user", "dlis.einvoice.approver");

    await admin.assignRole("novak", "dlis.einvoice.user", true, {
      [CHANNEL]: "SK,CZ",
    });
    assertEquals(await verify("novak", VIEW, "SK"), true);
    assertEquals(await verify("novak", APPROVE, "CZ"), true);
    assertEquals(await verify("novak", VIEW, "DE"), false);

    // Values belong to the assignment: approver for SK and viewer for CZ must
    // not approve CZ, unlike attributes merged across all of a user's roles.
    await admin.assignRole("svoboda", "dlis.einvoice.approver", true, {
      [CHANNEL]: "SK",
    });
    await admin.assignRole("svoboda", "dlis.einvoice.viewer", true, {
      [CHANNEL]: "CZ",
    });
    assertEquals(await verify("svoboda", APPROVE, "SK"), true);
    assertEquals(await verify("svoboda", APPROVE, "CZ"), false);
    assertEquals(await verify("svoboda", VIEW, "CZ"), true);
    assertEquals(await verify("svoboda", VIEW, "SK"), false);

    // Reassigning with attributes replaces them; omitting them keeps them.
    await admin.assignRole("svoboda", "dlis.einvoice.viewer", true, {
      [CHANNEL]: "DE",
    });
    await admin.assignRole("svoboda", "dlis.einvoice.viewer");
    assertEquals(await verify("svoboda", VIEW, "DE"), true);
    assertEquals(await verify("svoboda", VIEW, "CZ"), false);
    assertEquals(
      (await admin.userRoles("svoboda")).find((row) =>
        row.role === "dlis.einvoice.viewer"
      )?.attributes,
      { [CHANNEL]: "DE" },
    );

    // An unbound attribute grants nothing and is reported as such.
    await admin.assignRole("dvorak", "dlis.einvoice.viewer");
    assertEquals(await verify("dvorak", VIEW, "SK"), false);
    assertEquals(await permitsAny("dvorak", VIEW), false);
    fixture.asUser("dvorak");
    assertEquals(await check(VIEW, "SK"), false);
    fixture.asUser("system");
    const denied = await admin.failedChecks("dvorak");
    assert(
      denied.some((row) =>
        row.details.some((detail) => detail.reason === "unbound_attribute")
      ),
    );

    // Comparison mode binds through attributes as well.
    await admin.createRole({
      name: "limit",
      description: "",
      permissions: { "dlis.einvoice.amount.approve": { attribute: "limit" } },
    });
    await admin.assignRole("dvorak", "limit", true, {
      limit: { comparisons: "<=10000" },
    });
    assertEquals(
      await verify("dvorak", "dlis.einvoice.amount.approve", "9999.50"),
      true,
    );
    assertEquals(
      await verify("dvorak", "dlis.einvoice.amount.approve", "10000.01"),
      false,
    );

    assertEquals(await permitsAny("novak", VIEW), true);
    assertEquals(await permitsAny("novak", "dlis.einvoice.other"), false);
    assertEquals(await permitsAny("system", "anything"), true);
    assertEquals(
      (await filter("novak", [{ channel: "SK" }, { channel: "DE" }], {
        channel: VIEW,
      })).map((row) => row.channel),
      ["SK"],
    );
    assertEquals(await admin.roleAttributes("dlis.einvoice.user"), [CHANNEL]);
  } finally {
    fixture.close();
  }
});

Deno.test("SQL predicates substitute assignment attributes per entry", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  const { sqlPredicate } = await import("../mod.ts");
  const { db, sql } = await import("/p/the8020/db/mod.ts");
  try {
    await users.add("novak");
    fixture.database.exec(
      "create table documents (id integer, channel text); insert into documents values (1, 'SK'), (2, 'CZ'), (3, 'DE'), (4, 'AT')",
    );
    await admin.createRole({
      name: "viewer",
      description: "",
      permissions: { [VIEW]: { attribute: CHANNEL } },
    });
    await admin.createRole({
      name: "austria",
      description: "",
      permissions: { [VIEW]: "AT" },
    });
    await admin.assignRole("novak", "viewer", true, { [CHANNEL]: "*,!DE" });
    await admin.assignRole("novak", "austria");
    const predicate = await sqlPredicate("novak", VIEW, "channel");
    const rows = (await sql<
      { id: number }
    >`select id from documents where ${predicate} order by id`.execute(db))
      .rows;
    assertEquals(rows.map((row) => Number(row.id)), [1, 2, 4]);
  } finally {
    fixture.close();
  }
});

Deno.test("commands set attribute references and assignment values", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  const { command } = await import("./commands.ts");
  const { verify } = await import("../mod.ts");
  try {
    await users.add("novak");
    await command("create", ["viewer"]);
    await command("grant", ["viewer", VIEW, CHANNEL, "--attribute"]);
    assertEquals((await admin.getRole("viewer")).permissions[VIEW], {
      attribute: CHANNEL,
    });
    await command("assign", [
      "novak",
      "viewer",
      "--attribute",
      `${CHANNEL}=SK,CZ`,
      `--attribute-comparisons=limit=>=5`,
    ]);
    assertEquals(
      (await admin.userRoles("novak")).find((row) => row.role === "viewer")
        ?.attributes,
      { [CHANNEL]: "SK,CZ", limit: { comparisons: ">=5" } },
    );
    assertEquals(await verify("novak", VIEW, "CZ"), true);
    await assertRejects(() =>
      command("grant", ["viewer", VIEW, "x", "--attribute", "--comparisons"])
    );
    await assertRejects(() =>
      command("assign", ["novak", "viewer", "--attribute", "missing-equals"])
    );
    await assertRejects(() =>
      command("assign", [
        "novak",
        "viewer",
        "--attribute",
        `${CHANNEL}=SK`,
        "--attribute",
        `${CHANNEL}=CZ`,
      ])
    );
  } finally {
    fixture.close();
  }
});

Deno.test("users see their own roles without the users.view permission", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  try {
    for (const name of ["novak", "svoboda"]) await users.add(name);
    await admin.createRole({
      name: "dlis.einvoice.viewer",
      description: "View documents in your channels.",
      permissions: { [VIEW]: { attribute: CHANNEL } },
    });
    await admin.assignRole("novak", "dlis.einvoice.viewer", true, {
      [CHANNEL]: "SK",
    });
    fixture.asUser("novak");
    assertEquals(await admin.ownRoles(), [{
      role: "dlis.einvoice.viewer",
      automatic: false,
      explicit: true,
      attributes: { [CHANNEL]: "SK" },
      description: "View documents in your channels.",
    }]);
    // Another user's roles still need the permission.
    await assertRejects(() => admin.userRoles("svoboda"));
  } finally {
    fixture.close();
  }
});
