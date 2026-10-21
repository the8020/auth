/** Split on unescaped separators, retaining escapes for pattern matching. */
function split(source: string, separator: string): string[] {
  const parts = [""];
  for (let i = 0; i < source.length; i++) {
    const char = source[i]!;
    if (char === "\\") {
      if (++i === source.length) throw new TypeError("Incomplete escape");
      parts[parts.length - 1] += char + source[i];
    } else if (char === separator) parts.push("");
    else parts[parts.length - 1] += char;
  }
  return parts;
}

export function pattern(source: string): (value: string) => boolean {
  if (!source) {
    throw new TypeError("A nonempty pattern is required");
  }
  const tokens = source.match(/\\[\s\S]|[\s\S]/gu)!;
  if (tokens.includes("\\")) throw new TypeError("Incomplete escape");
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
export type PermissionValues = string | { comparisons: string };
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

function endpoint(source: string): string {
  if (
    !source ||
    source.match(/\\[\s\S]|[\s\S]/gu)!.some((token) =>
      token === "*" || token === "?" || token === "\\"
    )
  ) throw new TypeError("An ordered endpoint must be a literal value");
  return source.replace(/\\([\s\S])/gu, "$1");
}

function term(source: string, comparisons: boolean): ValueTerm {
  const comparison = comparisons && source.match(/^(!?)(>=|<=|>|<)(.*)$/s);
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
    pattern(source);
    return { kind: "pattern", source };
  }
  if (parts.length !== 2) {
    throw new TypeError(
      "Use two range endpoints; escape literal hyphens with \\-",
    );
  }
  const [start, end] = parts.map(endpoint) as [string, string];
  const numbers = numeric.test(start) && numeric.test(end);
  if (compare(start, end, numbers) > 0) {
    throw new TypeError("Range start exceeds its end");
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
  const comparisons = typeof input !== "string";
  if (
    comparisons &&
    (!input || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).length !== 1 || !Object.hasOwn(input, "comparisons") ||
      typeof input.comparisons !== "string")
  ) throw new TypeError("Expected a string or { comparisons: string }");
  const source = comparisons ? input.comparisons : input;
  return split(source, ",").map((part) => {
    part = part.trim();
    // Stored strings retain their original literal, exclusion and range semantics.
    const excluded = part.startsWith("!") &&
      !(comparisons && /^![<>]/.test(part));
    return {
      excluded,
      term: term(excluded ? part.slice(1) : part, comparisons),
    };
  });
}

export function compileExpression(terms: PermissionTerm[]) {
  const compiled = terms.map(({ excluded, term }) => ({
    excluded,
    matches: term.kind === "pattern"
      ? pattern(term.source)
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
