import { kernelDatabaseBackend } from "@the8020/kernel";
import {
  type Expression,
  type RawBuilder,
  sql,
  type SqlBool,
} from "/p/the8020/db/kysely.ts";
import { permissionsFor } from "./evaluation.ts";
import type { Comparison, ValueTerm } from "./matching.ts";

/** A bound predicate over a text reference. Does not audit or change the execution user. */
export async function sqlPredicate(
  username: string,
  action: string,
  field: string | Expression<string | null>,
): Promise<RawBuilder<SqlBool>> {
  const policy = (await permissionsFor(username, [action])).get(action)!;
  if (policy.reason === "role_limit") return sql<SqlBool>`false`;
  const grants = policy.entries.flatMap((entry) =>
    entry.terms ? [entry.terms] : []
  );
  if (!policy.bypass && !grants.length) return sql<SqlBool>`false`;
  for (const terms of grants) {
    for (const { term } of terms) {
      const values = term.kind === "pattern"
        ? [term.source]
        : term.bounds.map((bound) => bound.value);
      if (
        values.some((value) => value.includes("\0") || !value.isWellFormed())
      ) {
        throw new TypeError(
          "SQL permission values must be well-formed Unicode without NUL",
        );
      }
    }
  }
  const sqlite = kernelDatabaseBackend() === "sqlite";
  const ref = typeof field === "string" ? sql.ref(field) : field;
  const collation = sql.raw(sqlite ? "binary" : '"C"');
  const v = sql`auth_value.v`;
  const collate = (value: Expression<unknown>) =>
    sql`(${value} collate ${collation})`;
  const codepoint = (value: Expression<unknown>) =>
    sqlite ? sql`unicode(${value})` : sql`ascii(${value})`;
  const join = (parts: Expression<unknown>[], operator: "and" | "or") =>
    parts.length
      ? sql`(${sql.join(parts, sql.raw(` ${operator} `))})`
      : sql.raw(operator === "and" ? "true" : "false");
  const op = (operator: Comparison) => sql.raw(operator);
  const reverse = (operator: Comparison): Comparison =>
    ({ ">": "<", ">=": "<=", "<": ">", "<=": ">=" } as const)[operator];
  const number = (bound: string, operator: Comparison) => {
    const [whole, fraction = ""] = bound.replace(/^-/, "").split(".");
    const w = whole!.replace(/^0+/, ""), f = fraction.replace(/0+$/, "");
    const negative = bound.startsWith("-") && (w !== "" || f !== "");
    const magnitude = sql`(length(w), ${collate(sql`w`)}, ${collate(sql`f`)})`;
    const target = sql`(${w.length}, ${w}, ${f})`;
    // Text tuples preserve arbitrary decimal precision on SQLite as well as PostgreSQL.
    return sql`(valid and (case when negative <> ${negative}
      then (case when negative then -1 else 1 end) ${op(operator)} 0
      when negative then ${magnitude} ${op(reverse(operator))} ${target}
      else ${magnitude} ${op(operator)} ${target} end))`;
  };
  const lexical = (bound: string, operator: Comparison) => {
    if (
      !/[\uD800-\uFFFF]/u.test(bound) && !/[\u{10000}-\u{10FFFF}]/u.test(bound)
    ) {
      return sql`${collate(v)} ${op(operator)} ${bound}`;
    }
    // JS orders UTF-16 units; C/BINARY order Unicode scalars. Compare the first differing scalar in UTF-16 order.
    const rank = (value: Expression<unknown>) =>
      sql`(case when ${value} = '' then -1
      when ${codepoint(value)} between 57344 and 65535 then ${
        codepoint(value)
      } + 1114112
      else ${codepoint(value)} end)`;
    const c = sql`auth_chars.c`, b = sql`substr(${bound}, auth_chars.i, 1)`;
    const order = sql`coalesce((select case when ${rank(c)} < ${
      rank(b)
    } then -1 else 1 end
      from auth_chars where ${collate(c)} <> ${collate(b)} order by i limit 1),
      case when length(${v}) < ${Array.from(bound).length} then -1 else 0 end)`;
    return sql`${order} ${op(operator)} 0`;
  };
  const render = (term: ValueTerm): Expression<unknown> => {
    if (term.kind === "ordered") {
      return join(
        term.bounds.map(({ value, operator }) =>
          term.numbers ? number(value, operator) : lexical(value, operator)
        ),
        "and",
      );
    }
    const tokens = term.source.match(/\\[\s\S]|[\s\S]/gu)!;
    if (!tokens.some((token) => token === "*" || token === "?")) {
      return sql`${collate(v)} = ${
        tokens.map((token) => token.startsWith("\\") ? token.slice(1) : token)
          .join("")
      }`;
    }
    const glob = tokens.map((token) => {
      if (token === "*") return sqlite ? "*" : "%";
      if (token === "?") return sqlite ? "?" : "_";
      const literal = token.startsWith("\\") ? token.slice(1) : token;
      return sqlite
        ? literal.replace(/[\[*?]/g, (char) => `[${char}]`)
        : literal.replace(/[\\%_]/g, (char) => `\\${char}`);
    }).join("");
    return sqlite
      ? sql`${v} glob ${glob}`
      : sql`${collate(v)} like ${glob} escape ${"\\"}`;
  };
  const permitted = policy.bypass ? sql`true` : join(
    grants.map((terms) =>
      join([
        join(
          terms.filter((term) => !term.excluded).map(({ term }) =>
            render(term)
          ),
          "or",
        ),
        sql`not ${
          join(
            terms.filter((term) => term.excluded).map(({ term }) =>
              render(term)
            ),
            "or",
          )
        }`,
      ], "and")
    ),
    "or",
  );
  const numeric = grants.some((terms) =>
    terms.some(({ term }) => term.kind === "ordered" && term.numbers)
  );
  const numericCTEs = numeric
    ? sql`, auth_unsigned as (
      select ${v} as original, case when substr(${v}, 1, 1) = '-' then substr(${v}, 2) else ${v} end as u from auth_value
    ), auth_parts as (
      select original, u,
        ${
      sqlite ? sql`instr(u, '.')` : sql`strpos(u, '.')`
    } as dot from auth_unsigned
    ), auth_number as (
      select ${
      sqlite
        ? sql`(u <> '' and u not glob '*[^0-9.]*' and u not like '%.%.%' and substr(u, 1, 1) <> '.' and substr(u, -1) <> '.')`
        : sql`(original ~ ${"^-?[0-9]+([.][0-9]+)?$"})`
    } as valid,
        (substr(original, 1, 1) = '-' and replace(replace(u, '0', ''), '.', '') <> '') as negative,
        ltrim(case when dot = 0 then u else substr(u, 1, dot - 1) end, '0') as w,
        rtrim(case when dot = 0 then '' else substr(u, dot + 1) end, '0') as f
      from auth_parts
    )`
    : sql``;
  const text = sqlite
    ? sql`typeof(${v}) = 'text' and instr(${v}, char(0)) = 0`
    : sql`${v} is not null`;
  // The public scalar limit counts UTF-16 units; SQL length counts Unicode scalars.
  const length =
    sql`(case when length(${v}) <= 1024 then true when length(${v}) > 2048 then false
    else (select sum(case when ${
      codepoint(sql`c`)
    } > 65535 then 2 else 1 end) <= 2048 from auth_chars) end)`;
  return sql<SqlBool>`(with recursive auth_value(v) as (select ${ref}),
    auth_chars(i, c) as (
      select 1, substr(${v}, 1, 1) from auth_value where length(${v}) > 0
      union all select i + 1, substr(${v}, i + 1, 1) from auth_chars cross join auth_value where i < length(${v}) and i < 2048
    )${numericCTEs}
    select coalesce((${text}) and ${length} and (${permitted}), false)
    from auth_value ${numeric ? sql`cross join auth_number` : sql``})`;
}
