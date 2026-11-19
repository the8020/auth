import { text as formatMessage } from "/p/the8020/i18n/mod.ts";
import { msg as messageSymbol } from "/p/the8020/auth/i18n/messages.ts";
/** Split outside quoted literals, retaining quotes and escapes for parsing. */
function split(source: string, separator: string): string[] {
  const parts = [""];
  let quoted = false;
  for (let i = 0; i < source.length; i++) {
    const char = source[i]!;
    if (char === "\\") {
      if (++i === source.length) {
        throw new TypeError(
          formatMessage(messageSymbol("errors.incomplete_escape")),
        );
      }
      parts[parts.length - 1] += char + source[i];
    } else if (char === separator && !quoted) parts.push("");
    else {
      if (char === '"') quoted = !quoted;
      parts[parts.length - 1] += char;
    }
  }
  if (quoted) {
    throw new TypeError(
      formatMessage(messageSymbol("errors.unclosed_quoted_value")),
    );
  }
  return parts;
}

export function pattern(source: string): (value: string) => boolean {
  if (!source) {
    throw new TypeError(
      formatMessage(messageSymbol("errors.a_nonempty_pattern_is_required")),
    );
  }
  const tokens = source.match(/\\[\s\S]|[\s\S]/gu)!;
  if (tokens.includes("\\")) {
    throw new TypeError(
      formatMessage(messageSymbol("errors.incomplete_escape")),
    );
  }
  return (value) => {
    const chars = Array.from(value);
    let p = 0, v = 0, star = -1, retry = 0;
    // Bounded greedy glob matching avoids regular-expression backtracking.
    while (v < chars.length) {
      const token = tokens[p];
      if (token === "*") {
        star = p++;
        retry = v;
      } else if (
        token === "?" ||
        (token?.startsWith("\\") ? token.slice(1) : token) === chars[v]
      ) {
        p++;
        v++;
      } else if (star >= 0) {
        p = star + 1;
        v = ++retry;
      } else return false;
    }
    while (tokens[p] === "*") p++;
    return p === tokens.length;
  };
}

export const numeric = /^-?\d+(?:\.\d+)?$/;
/** Automatic expressions; the object form remains readable for stored entries. */
export type PermissionValues = string | { comparisons: string };
/** A role entry whose values come from the assignment that reached the role. */
export type AttributeReference = { attribute: string };
/** What a role entry stores: an expression or an attribute reference. */
export type RoleEntryValues = PermissionValues | AttributeReference;

export function isAttributeReference(
  values: unknown,
): values is AttributeReference {
  return typeof values === "object" && values !== null &&
    !Array.isArray(values) && Object.keys(values).length === 1 &&
    typeof (values as { attribute?: unknown }).attribute === "string";
}
export type Comparison = ">" | ">=" | "<" | "<=";
export type ValueTerm =
  | { kind: "pattern"; source: string }
  | {
    kind: "ordered";
    numbers: boolean;
    bounds: { operator: Comparison; value: string }[];
  };
export interface PermissionTerm {
  excluded: boolean;
  term: ValueTerm;
}

function compare(a: string, b: string, numbers: boolean): number {
  if (!numbers) return a < b ? -1 : a > b ? 1 : 0;
  const scale = Math.max(
    a.split(".")[1]?.length ?? 0,
    b.split(".")[1]?.length ?? 0,
  );
  const scaled = (s: string) => {
    const [whole, fraction = ""] = s.split(".");
    return BigInt(whole! + fraction.padEnd(scale, "0"));
  };
  const left = scaled(a), right = scaled(b);
  return left < right ? -1 : left > right ? 1 : 0;
}

function quotedValue(source: string): string {
  if (!/^"(?:\\[\s\S]|[^"\\])*"$/u.test(source)) {
    throw new TypeError(
      formatMessage(messageSymbol("errors.quote_the_complete_literal_value")),
    );
  }
  return source.slice(1, -1).replace(/\\([\s\S])/gu, "$1");
}

function endpoint(source: string): string {
  if (source.startsWith('"')) return quotedValue(source);
  if (
    !source ||
    source.match(/\\[\s\S]|[\s\S]/gu)!.some((token) =>
      token === "*" || token === "?" || token === "\\" || token === '"'
    )
  ) {
    throw new TypeError(
      formatMessage(
        messageSymbol("errors.an_ordered_endpoint_must_be_a_literal_value"),
      ),
    );
  }
  return source.replace(/\\([\s\S])/gu, "$1");
}

function term(source: string): ValueTerm {
  if (source.startsWith('"')) {
    return {
      kind: "pattern",
      source: quotedValue(source).replace(/[\\*?]/gu, "\\$&"),
    };
  }
  const comparison = source.match(/^(!?)(>=|<=|>|<)(.*)$/s);
  if (comparison) {
    let operator = comparison[2] as Comparison;
    if (comparison[1]) {
      operator =
        ({ ">": "<=", ">=": "<", "<": ">=", "<=": ">" } as const)[operator];
    }
    const value = endpoint(comparison[3]!);
    return {
      kind: "ordered",
      numbers: numeric.test(value),
      bounds: [{ operator, value }],
    };
  }
  if (numeric.test(source)) return { kind: "pattern", source };
  const numberRange = source.match(/^(-?\d+(?:\.\d+)?)-(-?\d+(?:\.\d+)?)$/);
  const parts = numberRange ? numberRange.slice(1) : split(source, "-");
  if (parts.length === 1) {
    if (source.match(/\\[\s\S]|[\s\S]/gu)?.includes('"')) {
      throw new TypeError(
        formatMessage(messageSymbol("errors.quote_the_complete_literal_value")),
      );
    }
    pattern(source);
    return { kind: "pattern", source };
  }
  if (parts.length !== 2) {
    throw new TypeError(
      formatMessage(
        messageSymbol(
          "errors.use_two_range_endpoints_quote_literal_text_containing_hyphens",
        ),
      ),
    );
  }
  const [start, end] = parts.map(endpoint) as [string, string];
  const numbers = numeric.test(start) && numeric.test(end);
  if (compare(start, end, numbers) > 0) {
    throw new TypeError(
      formatMessage(messageSymbol("errors.range_start_exceeds_its_end")),
    );
  }
  return {
    kind: "ordered",
    numbers,
    bounds: [
      { operator: ">=", value: start },
      { operator: "<=", value: end },
    ],
  };
}

/** Parse once; evaluators and SQL consume the same normalized terms. */
export function parseExpression(input: PermissionValues): PermissionTerm[] {
  const wrapped = typeof input !== "string";
  if (
    wrapped &&
    (!input || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).length !== 1 || !Object.hasOwn(input, "comparisons") ||
      typeof input.comparisons !== "string")
  ) {
    throw new TypeError(
      formatMessage(messageSymbol("errors.expected_a_string_or")),
    );
  }
  const source = wrapped ? input.comparisons : input;
  return split(source, ",").map((part) => {
    part = part.trim();
    const excluded = part.startsWith("!") &&
      !/^![<>]/.test(part);
    return {
      excluded,
      term: term(excluded ? part.slice(1) : part),
    };
  });
}

export function compileExpression(terms: PermissionTerm[]) {
  const compiled = terms.map(({ excluded, term }) => ({
    excluded,
    matches: term.kind === "pattern"
      ? term.source === ""
        ? (value: string) => value === ""
        : pattern(term.source)
      : (value: string) =>
        (!term.numbers || numeric.test(value)) &&
        term.bounds.every(({ operator, value: bound }) => {
          const order = compare(value, bound, term.numbers);
          return operator === ">"
            ? order > 0
            : operator === ">="
            ? order >= 0
            : operator === "<"
            ? order < 0
            : order <= 0;
        }),
  }));
  return (value: string): "allowed" | "excluded" | "no_value_match" => {
    let allowed = false;
    for (const term of compiled) {
      if (!term.matches(value)) continue;
      if (term.excluded) return "excluded";
      allowed = true;
    }
    return allowed ? "allowed" : "no_value_match";
  };
}

export function expression(source: PermissionValues) {
  return compileExpression(parseExpression(source));
}
