import { assert, assertEquals } from "@std/assert";
import { kernelDatabaseBackendSymbol } from "@the8020/kernel";
import { comparisonCases } from "./permission_cases.ts";
import { authDatabase } from "./test_support.ts";

const enabled = (await Deno.permissions.query({
      name: "env",
      variable: "AUTH_TEST_POSTGRES",
    })).state === "granted" && Deno.env.get("AUTH_TEST_POSTGRES") === "1";
Deno.test({
  name: "executed PostgreSQL predicates match shared verify/filter cases",
  ignore: !enabled,
  async fn() {
    const fixture = await authDatabase();
    const { check, verify, filter, sqlPredicate } = await import("../mod.ts");
    const { createDatabase } = await import("/p/the8020/db/src/runtime.ts");
    const { sql } = await import("/p/the8020/db/kysely.ts");
    const admin = await import("./admin.ts");
    const users = await import("/p/the8020/users/src/admin.ts");
    const compiler = createDatabase("postgresql");
    const globals = globalThis as unknown as Record<symbol, unknown>;
    const literal = (value: unknown): string => {
      if (value === null) return "null";
      if (typeof value === "boolean" || typeof value === "number") {
        return String(value);
      }
      if (typeof value !== "string") {
        throw new TypeError("Unexpected test SQL parameter");
      }
      return `'${value.replace(/'/g, "''")}'`;
    };
    const statements = [
      "begin; set standard_conforming_strings = on; create temp table auth_items (id integer, value text);",
    ];
    const expected: string[] = [];
    try {
      await users.add("alice");
      await admin.createRole({
        name: "alice",
        description: "",
        permissions: {},
      });
      const collect = async (
        username: string,
        values: (string | null)[],
        ids: number[],
      ) => {
        const rows = values.map((value, id) => ({ id, value }));
        const filtered = await filter(username, rows, { value: "items.view" });
        assertEquals(filtered.map((row) => row.id), ids);
        globals[kernelDatabaseBackendSymbol] = "postgresql";
        const predicate = await sqlPredicate(
          username,
          "items.view",
          "item.value",
        );
        globals[kernelDatabaseBackendSymbol] = "sqlite";
        const compiled =
          sql`select coalesce(string_agg(id::text, ',' order by id), '') from auth_items as item where ${predicate}`
            .compile(compiler);
        const index = expected.length;
        statements.push(
          "delete from auth_items;",
          `insert into auth_items values ${
            rows.map((row) => `(${row.id},${literal(row.value)})`).join(",")
          };`,
        );
        // PREPARE exercises PostgreSQL's typed bound-parameter path; fixtures contain no secrets.
        statements.push(
          `prepare auth_case_${index} as ${compiled.sql};`,
          `execute auth_case_${index}${
            compiled.parameters.length
              ? `(${compiled.parameters.map(literal).join(",")})`
              : ""
          };`,
        );
        expected.push(filtered.map((row) => row.id).join(","));
      };
      for (const [source, allowed, denied] of comparisonCases) {
        if (typeof source === "string") {
          fixture.database.prepare(
            "update the8020__auth__roles set permissions = ? where name = ?",
          ).run(JSON.stringify({ "items.view": source }), "alice");
        } else await admin.setPermission("alice", "items.view", source);
        fixture.asUser("alice");
        for (const [id, value] of [...allowed, ...denied].entries()) {
          assertEquals(
            await verify("alice", "items.view", value),
            id < allowed.length,
          );
          assertEquals(await check("items.view", value), id < allowed.length);
        }
        fixture.asUser("system");
        await collect(
          "alice",
          [...allowed, ...denied, null],
          allowed.map((_, id) => id),
        );
      }
      await users.add("bob");
      await collect("bob", ["x", null], []);
      await collect("ghost", ["x", null], []);
      const long = [
        "a".repeat(2048),
        "a".repeat(2049),
        "😀".repeat(1024),
        "😀".repeat(1025),
        null,
      ];
      await collect("alice", long, [0, 2]);
      await collect("system", long, [0, 2]);
      await admin.setPermission("alice", "items.view", "10-30,!20");
      await admin.createRole({
        name: "extra",
        description: "",
        permissions: { "items.*": "20" },
      });
      await admin.includeRole("alice", "extra");
      await collect("alice", ["10", "20", "30", "31", null], [0, 1, 2]);
      statements.push("rollback;");
      const process = new Deno.Command("psql", {
        args: ["-X", "-qAt", "--set=ON_ERROR_STOP=1"],
        stdin: "piped",
        stdout: "piped",
        stderr: "piped",
      }).spawn();
      const writer = process.stdin.getWriter();
      await writer.write(new TextEncoder().encode(statements.join("\n")));
      await writer.close();
      const result = await process.output();
      assert(result.success, new TextDecoder().decode(result.stderr));
      assertEquals(
        new TextDecoder().decode(result.stdout).slice(0, -1).split("\n"),
        expected,
      );
    } finally {
      globals[kernelDatabaseBackendSymbol] = "sqlite";
      await compiler.destroy();
      fixture.close();
    }
  },
});
