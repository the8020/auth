import { value as valueField } from "../types/auth.ts";
import { evaluate, permissionsFor } from "./evaluation.ts";

/** Read-only permission query for an explicit username (not a user:<name> ID). */
export async function verify(
  username: string,
  action: string,
  value: string,
): Promise<boolean> {
  valueField.parse(value);
  return evaluate(
    (await permissionsFor(username, [action])).get(action)!,
    value,
  ).allowed;
}

/** Each own property maps to one scalar action; all mapped checks must pass. */
export async function filter<T extends object>(
  username: string,
  rows: readonly T[],
  mapping: Partial<Record<keyof T, string>>,
): Promise<T[]> {
  const fields = (Reflect.ownKeys(mapping) as (keyof T)[]).map((property) => ({
    property,
    action: mapping[property]!,
  }));
  if (!fields.length) {
    throw new TypeError("At least one property/action mapping is required");
  }
  const policies = await permissionsFor(
    username,
    fields.map(({ action }) => action),
  );
  return rows.filter((row) =>
    fields.every(({ property, action }) => {
      if (
        row === null || typeof row !== "object" || !Object.hasOwn(row, property)
      ) return false;
      const value = row[property];
      return typeof value === "string" && value.length <= 2048 &&
        evaluate(policies.get(action)!, value).allowed;
    })
  );
}
