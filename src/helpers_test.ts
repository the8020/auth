import { assert, assertEquals, assertRejects, assertThrows } from "@std/assert";
import { expression, type PermissionValues } from "./matching.ts";
import { comparisonCases, legacyCases } from "./permission_cases.ts";
import { authDatabase } from "./test_support.ts";

Deno.test("comparison grammar normalizes aliases, preserves ranges and rejects incomplete input", () => {
  for (const [source, allowed, denied] of comparisonCases) {
    const match = expression(source);
    for (const value of allowed) {
      assertEquals(match(value), "allowed", `${source}: ${value}`);
    }
    for (const value of denied) {
      assert(match(value) !== "allowed", `${source}: ${value}`);
    }
  }
  for (const source of [">", "!>=", "<=*", ">?", ">abc\\", "9-1"]) {
    assertThrows(() => expression({ comparisons: source }));
  }
});

Deno.test("permission edits preserve stored strings and explicitly opt into comparisons", async () => {
  const fixture = await authDatabase();
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  const { command } = await import("./commands.ts");
  const { check, verify, filter, sqlPredicate } = await import("../mod.ts");
  const { db, sql } = await import("/p/the8020/db/mod.ts");
  try {
    await users.add("alice");
    await admin.createRole({ name: "alice", description: "", permissions: {} });
    const legacy = Object.fromEntries(
      legacyCases.map(([source], i) => [`old.${i}`, source]),
    );
    const seed = (entries: Record<string, unknown>) =>
      fixture.database.prepare(
        "update the8020__auth__roles set permissions = ? where name = ?",
      ).run(JSON.stringify(entries), "alice");
    seed(legacy);
    const loaded = await admin.getRole("alice");
    assertEquals(loaded.permissions, legacy);
    await admin.saveRole({ ...loaded, description: "Edited description" });
    await admin.setPermission("alice", "new", { comparisons: ">10" });
    assertEquals((await admin.getRole("alice")).permissions, {
      ...legacy,
      new: { comparisons: ">10" },
    });
    assertEquals(await verify("alice", "old.0", "11"), false);
    assertEquals(await verify("alice", "new", "11"), true);
    await command("grant", ["alice", "command", ">10"]);
    assertEquals(await verify("alice", "command", "11"), false);
    assertEquals(await verify("alice", "command", ">10"), true);
    await command("grant", ["alice", "command", ">10", "--comparisons"]);
    assertEquals(await verify("alice", "command", "11"), true);
    assertEquals((await admin.getRole("alice")).permissions.command, {
      comparisons: ">10",
    });
    await command("create", [
      "new-role",
      "--permissions",
      JSON.stringify({
        new: { comparisons: "!>10" },
        old: ">10",
      }),
    ]);
    assertEquals((await admin.getRole("new-role")).permissions, {
      new: { comparisons: "!>10" },
      old: ">10",
    });
    for (
      const invalid of [null, [], 10, {}, { comparisons: 10 }, {
        comparisons: "*",
        other: true,
      }]
    ) {
      const input = invalid as PermissionValues;
      assertThrows(() => expression(input));
      await assertRejects(() => admin.setPermission("alice", "invalid", input));
      seed({ invalid });
      fixture.asUser("alice");
      assertEquals(await check("invalid", "11"), false);
      assertEquals(await verify("alice", "invalid", "11"), false);
      assertEquals(
        await filter("alice", [{ value: "11" }], { value: "invalid" }),
        [],
      );
      const predicate = await sqlPredicate("alice", "invalid", sql.lit("11"));
      assertEquals(
        (await sql`select 1 where ${predicate}`.execute(db)).rows,
        [],
      );
      fixture.asUser("system");
    }
  } finally {
    fixture.close();
  }
});

Deno.test("verify, filter and executed SQLite predicates agree without audits", async () => {
  const fixture = await authDatabase();
  const {
    verify,
    filter,
    sqlPredicate,
    check,
    requirePermission,
    AuthorizationError,
  } = await import("../mod.ts");
  const { db, sql } = await import("/p/the8020/db/mod.ts");
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  const Failures = (await import("../tables/failures.ts")).default;
  try {
    await users.add("alice");
    await users.add("bob");
    await admin.createRole({ name: "alice", description: "", permissions: {} });
    fixture.database.exec(
      "create table auth_items (id integer primary key, value, other)",
    );
    for (const [source, allowed, denied] of comparisonCases) {
      if (typeof source === "string") {
        fixture.database.prepare(
          "update the8020__auth__roles set permissions = ? where name = ?",
        ).run(JSON.stringify({ "items.view": source }), "alice");
      } else await admin.setPermission("alice", "items.view", source);
      const rows = [...allowed, ...denied, null, 10].map((value, id) =>
        Object.freeze({ id, value })
      );
      fixture.database.exec("delete from auth_items");
      for (const row of rows) {
        fixture.database.prepare(
          "insert into auth_items (id, value) values (?, ?)",
        ).run(row.id, row.value);
      }
      const before = fixture.queries.length;
      const filtered = await filter("alice", Object.freeze(rows), {
        value: "items.view",
      });
      const reads = fixture.queries.slice(before);
      assertEquals(
        reads.length,
        4,
        "one user, assignment, role and inclusion read",
      );
      assertEquals(
        reads.filter((query) => query.includes('from "the8020__auth__roles"'))
          .length,
        1,
      );
      assertEquals(
        filtered.map((row) => row.id),
        allowed.map((_, i) => i),
        JSON.stringify(source),
      );
      assert(filtered.every((row) => rows[row.id] === row));
      const sqlStart = fixture.queries.length;
      const predicate = await sqlPredicate("alice", "items.view", "item.value");
      assertEquals(fixture.queries.length - sqlStart, 4);
      const query = sql<
        { id: number }
      >`select id from auth_items as item where ${predicate} order by id`;
      const selected = (await query.execute(db)).rows;
      assertEquals(
        selected.map((row) => row.id),
        filtered.map((row) => row.id),
        JSON.stringify(source),
      );
      for (const [id, value] of [...allowed, ...denied].entries()) {
        assertEquals(
          await verify("alice", "items.view", value),
          id < allowed.length,
          `${source}: ${value}`,
        );
      }
      fixture.asUser("alice");
      for (const [id, value] of [...allowed, ...denied].entries()) {
        assertEquals(await check("items.view", value), id < allowed.length);
      }
      assertEquals(
        (await Failures.selectAll().execute()).length,
        denied.length,
      );
      fixture.database.exec("delete from the8020__auth__failures");
      fixture.asUser("system");
      if (JSON.stringify(source).includes("OR 1=1")) {
        const compiled = query.compile(db);
        assert(!compiled.sql.includes("OR 1=1"));
        assert(compiled.parameters.includes("x' OR 1=1 --"));
      }
    }
    assertEquals(await Failures.selectAll().execute(), []);
    fixture.asUser("alice");
    assertEquals(await check("missing", "x"), false);
    assertEquals((await Failures.selectAll().execute()).length, 1);
    await assertRejects(
      () => requirePermission("missing", "x"),
      AuthorizationError,
    );
    assertEquals((await Failures.selectAll().execute()).length, 2);
    assertEquals(await check("items.view", ""), true);
    assertEquals(await verify("system", "missing", "x"), true);
    assertEquals(
      await check("missing", "x"),
      false,
      "explicit verification never changes the trusted caller",
    );
    assertEquals((await Failures.selectAll().execute()).length, 3);
    await assertRejects(() =>
      verify("alice", "items.view", null as unknown as string)
    );
    await assertRejects(() => filter("alice", [{ value: "a" }], {}));
    const symbol = Symbol("region");
    assertEquals(
      await filter("alice", [{ value: "yes", [symbol]: "EU" }], {
        value: "items.view",
        [symbol]: "missing",
      }),
      [],
      "symbol mappings cannot be silently skipped",
    );
    const invalid = [{ value: null }, {}, { value: 10 }, {
      value: "a".repeat(2049),
    }];
    assertEquals(await filter("system", invalid, { value: "items.view" }), []);
    assertEquals(
      await filter("alice", [Object.create({ value: "yes" })], {
        value: "items.view",
      }),
      [],
    );
    for (const username of ["bob", "ghost", "user:alice"]) {
      assertEquals(await verify(username, "items.view", "a"), false);
      assertEquals(
        await filter(username, [{ value: "a" }], { value: "items.view" }),
        [],
      );
      const predicate = await sqlPredicate(username, "items.view", "value");
      assertEquals(
        (await sql`select id from auth_items where ${predicate}`.execute(db))
          .rows,
        [],
      );
    }
    fixture.asUser("system");
    await admin.createRole({
      name: "ghost",
      description: "",
      permissions: { "*": "*" },
    });
    assertEquals(
      await verify("ghost", "items.view", "a"),
      false,
      "orphaned roles do not resolve unknown users",
    );
    fixture.asUser("ghost");
    assertEquals(
      await check("items.view", "a"),
      true,
      "trusted service principals retain their existing role-based checks without account rows",
    );
    fixture.asUser("system");
    await admin.createRole({
      name: "extra",
      description: "",
      permissions: { "items.*": "20", "region.view": "EU" },
    });
    await admin.setPermission("alice", "items.view", "10-30,!20");
    await admin.includeRole("alice", "extra");
    await admin.includeRole("extra", "alice");
    const records = Object.freeze([
      Object.freeze({ value: "20", region: "EU" }),
      Object.freeze({ value: "10", region: "US" }),
      Object.freeze({ value: "30", region: "EU" }),
      Object.freeze({ value: "31", region: "EU" }),
    ]);
    const start = fixture.queries.length;
    assertEquals(
      await filter("alice", records, {
        value: "items.view",
        region: "region.view",
      }),
      [records[0], records[2]],
    );
    assertEquals(
      fixture.queries.length - start,
      6,
      "one traversal for both properties and all rows, including the cycle",
    );
    assertEquals(
      await verify("alice", "items.view", "20"),
      true,
      "another entry restores a local exclusion",
    );
    const extraPredicate = await sqlPredicate(
      "alice",
      "items.view",
      sql.ref<string>("value"),
    );
    fixture.database.exec(
      "delete from auth_items; insert into auth_items values (1, '20', null), (2, '31', null)",
    );
    assertEquals(
      (await sql`select id from auth_items where ${extraPredicate}`.execute(db))
        .rows,
      [{ id: 1 }],
    );
    await admin.includeRole("alice", "extra", false);
    assertEquals(
      await verify("alice", "items.view", "20"),
      false,
      "no cross-invocation cache",
    );
    fixture.database.prepare(
      "update the8020__auth__roles set permissions = ? where name = ?",
    ).run(JSON.stringify({ "items.view": { comparisons: ">" } }), "alice");
    assertEquals(await verify("alice", "items.view", "anything"), false);
    assertEquals(
      (await sql`select id from auth_items where ${await sqlPredicate(
        "alice",
        "items.view",
        "value",
      )}`.execute(db)).rows,
      [],
    );
    assertEquals((await Failures.selectAll().execute()).length, 3);
    fixture.database.exec("drop table the8020__auth__failures");
    assertEquals(await verify("alice", "missing", "x"), false);
    assertEquals(
      await filter("alice", [{ value: "x" }], { value: "missing" }),
      [],
    );
    await sqlPredicate("alice", "missing", "value");
    fixture.asUser("alice");
    await assertRejects(() => check("missing", "x"));
    fixture.database.exec("drop table the8020__auth__roles");
    await assertRejects(() => verify("alice", "items.view", "x"));
  } finally {
    fixture.close();
  }
});

Deno.test("SQL text domain, length limits, identifiers, composition and role cap fail closed", async () => {
  const fixture = await authDatabase();
  const { verify, filter, sqlPredicate, check } = await import("../mod.ts");
  const { db, sql } = await import("/p/the8020/db/mod.ts");
  const admin = await import("./admin.ts");
  const users = await import("/p/the8020/users/src/admin.ts");
  const Failures = (await import("../tables/failures.ts")).default;
  try {
    await users.add("alice");
    await admin.createRole({
      name: "alice",
      description: "",
      permissions: { "items.*": "*" },
    });
    fixture.database.exec(
      "create table auth_items (id integer, value collate nocase)",
    );
    const rows = [
      "a".repeat(2048),
      "a".repeat(2049),
      "😀".repeat(1024),
      "😀".repeat(1025),
      null,
      1,
      "\0x",
    ].map((value, id) => ({ id, value }));
    for (const row of rows) {
      fixture.database.prepare("insert into auth_items values (?, ?)").run(
        row.id,
        row.value,
      );
    }
    const predicate = await sqlPredicate("alice", "items.view", "value");
    assertEquals(
      (await sql`select id from auth_items where ${predicate} order by id`
        .execute(db)).rows,
      [{ id: 0 }, { id: 2 }],
    );
    assertEquals(
      (await sql`select id from auth_items where ${await sqlPredicate(
        "system",
        "items.view",
        "value",
      )} order by id`.execute(db)).rows,
      [{ id: 0 }, { id: 2 }],
    );
    assertEquals(
      (await filter("alice", rows.slice(0, -1), { value: "items.view" })).map((
        row,
      ) => row.id),
      [0, 2],
    );
    await assertRejects(() => verify("alice", "items.view", "😀".repeat(1025)));
    for (const value of ["\0*", "\uD800"]) {
      await admin.setPermission("alice", "items.*", value);
      await assertRejects(
        () => sqlPredicate("alice", "items.view", "value"),
        TypeError,
        "well-formed Unicode without NUL",
      );
    }
    await admin.setPermission("alice", "items.*", "Case");
    fixture.database.exec(
      "delete from auth_items; insert into auth_items values (1, 'Case'), (2, 'case')",
    );
    const left = await sqlPredicate("alice", "items.view", "item.value");
    const right = await sqlPredicate("alice", "items.other", "item.value");
    assertEquals(
      (await sql`select id from auth_items item where ${left} and ${right} and id > ${0}`
        .execute(db)).rows,
      [{ id: 1 }],
    );
    const attack = 'value") OR 1=1 --';
    const malicious = await sqlPredicate(
      "alice",
      "items.view",
      sql.ref(`item.${attack}`),
    );
    const query = sql`select id from auth_items item where ${malicious}`;
    assert(query.compile(db).sql.includes('"item"."value"") OR 1=1 --"'));
    await assertRejects(() => query.execute(db));
    await admin.setPermission("alice", "items.*", "*");
    fixture.database.exec(
      `with recursive n(i) as (select 1 union all select i + 1 from n where i < 10001)
      insert into the8020__auth__user_roles (username, role) select 'alice', 'limit-' || i from n`,
    );
    assertEquals(await verify("alice", "items.view", "yes"), false);
    assertEquals(
      await filter("alice", [{ value: "yes" }], { value: "items.view" }),
      [],
    );
    assertEquals(
      (await sql`select id from auth_items where ${await sqlPredicate(
        "alice",
        "items.view",
        "value",
      )}`.execute(db)).rows,
      [],
    );
    fixture.asUser("alice");
    assertEquals(await check("items.view", "yes"), false);
    const failures = await Failures.selectAll().execute();
    assertEquals(failures.length, 1);
    assertEquals(failures[0]!.reason, "role_limit");
  } finally {
    fixture.close();
  }
});
