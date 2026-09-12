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

const numeric = /^-?\d+(?:\.\d+)?$/;

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

function term(source: string): (value: string) => boolean {
  if (numeric.test(source)) return pattern(source);
  const numberRange = source.match(/^(-?\d+(?:\.\d+)?)-(-?\d+(?:\.\d+)?)$/);
  const parts = numberRange ? numberRange.slice(1) : split(source, "-");
  if (parts.length === 1) return pattern(source);
  if (
    parts.length !== 2 ||
    parts.some((part) =>
      !part ||
      part.match(/\\[\s\S]|[\s\S]/gu)!.some((token) =>
        token === "*" || token === "?"
      )
    )
  ) {
    throw new TypeError(
      "Use two range endpoints; escape literal hyphens with \\-",
    );
  }
  const [start, end] = parts.map((part) =>
    part.replace(/\\([\s\S])/gu, "$1")
  ) as [string, string];
  const numbers = numeric.test(start) && numeric.test(end);
  if (compare(start, end, numbers) > 0) {
    throw new TypeError("Range start exceeds its end");
  }
  return (value) =>
    (!numbers || numeric.test(value)) && compare(start, value, numbers) <= 0 &&
    compare(value, end, numbers) <= 0;
}

export function expression(
  source: string,
): (value: string) => "allowed" | "excluded" | "no_value_match" {
  const terms = split(source, ",").map((part) => {
    part = part.trim();
    const excluded = part.startsWith("!");
    return { excluded, matches: term(excluded ? part.slice(1) : part) };
  });
  return (value) => {
    let allowed = false;
    for (const term of terms) {
      if (!term.matches(value)) continue;
      if (term.excluded) return "excluded";
      allowed = true;
    }
    return allowed ? "allowed" : "no_value_match";
  };
}
