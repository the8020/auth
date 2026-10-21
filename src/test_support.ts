import { DatabaseSync } from "node:sqlite";
import {
  kernelDatabaseBackendSymbol,
  kernelInvokeSymbol,
} from "@the8020/kernel";
import { installContextProvider } from "../../kernel/defaults/config/runtime/deno/context/runtime.ts";

/** SQLite bridge for the auth tests and their browser fixture. */
export async function authDatabase() {
  const globals = globalThis as unknown as Record<symbol, unknown>;
  const previous = globals[kernelInvokeSymbol];
  const previousBackend = globals[kernelDatabaseBackendSymbol];
  globals[kernelDatabaseBackendSymbol] = "sqlite";
  const { descriptorOf } = await import("/p/the8020/db/mod.ts");
  const database = new DatabaseSync(":memory:");
  for (
    const module of [
      "auth/tables/roles",
      "auth/tables/user_roles",
      "auth/tables/role_includes",
      "auth/tables/failures",
      "users/tables/users",
      "users/tables/sessions",
      "users/tables/certificates",
      "system/tables/settings",
    ]
  ) {
    const descriptor = descriptorOf(
      (await import(`/p/the8020/${module}.ts`)).default,
    );
    const columns = descriptor.columns.map((column) =>
      `"${column.name}" ${
        ["integer", "boolean"].includes(column.logical_type)
          ? "INTEGER"
          : "TEXT"
      }`
    );
    columns.push(
      `PRIMARY KEY (${
        descriptor.primary_key.map((key) => `"${key}"`).join(",")
      })`,
    );
    database.exec(
      `CREATE TABLE "${descriptor.table_id}" (${columns.join(",")})`,
    );
  }
  const queries: string[] = [];
  const calls: { operation: string; input: Record<string, unknown> }[] = [];
  globals[kernelInvokeSymbol] = (
    operation: string,
    input: Record<string, unknown>,
  ) => {
    if (operation.startsWith("database.transaction.")) {
      const action = operation.split(".").at(-1)!;
      database.exec(action === "begin" ? "BEGIN" : action.toUpperCase());
      return Promise.resolve({ transaction: "transaction" });
    }
    if (operation === "runtime.operation") {
      calls.push({
        operation: String(input.operation),
        input: input.input as Record<string, unknown>,
      });
      return Promise.resolve({
        success: true,
        result: { service: {}, package: {} },
      });
    }
    if (operation !== "database.execute") {
      throw new Error(`Unexpected operation ${operation}`);
    }
    queries.push(String(input.statement));
    const parameters = (input.parameters as unknown[]).map((value) => {
      if (value !== null && typeof value === "object") {
        const tagged = value as { type: string; value: string | boolean };
        return tagged.type === "boolean"
          ? Number(tagged.value)
          : tagged.type === "json"
          ? JSON.stringify(tagged.value)
          : tagged.value;
      }
      return typeof value === "boolean" ? Number(value) : value;
    }) as (string | number | null)[];
    const statement = database.prepare(String(input.statement));
    if (input.return_rows) {
      const rows = statement.all(...parameters),
        columns = Object.keys(rows[0] ?? {});
      return Promise.resolve({
        columns,
        rows: rows.map((row) => columns.map((column) => row[column])),
      });
    }
    const result = statement.run(...parameters);
    return Promise.resolve({
      columns: [],
      rows: [],
      affected_rows: { type: "bigint", value: String(result.changes) },
    });
  };
  let username = "system";
  const restore = installContextProvider(() => ({
    type: "program",
    id: "the8020/auth/test",
    userId: `user:${username}`,
    username,
    authenticated: true,
    nodeId: "test",
    sandboxId: "test",
    workerId: "test",
    contextId: "test",
  }));
  return {
    database,
    calls,
    queries,
    asUser(name: string) {
      username = name;
    },
    close() {
      restore();
      globals[kernelInvokeSymbol] = previous;
      globals[kernelDatabaseBackendSymbol] = previousBackend;
      database.close();
    },
  };
}
