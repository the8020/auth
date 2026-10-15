import { parse } from "/p/the8020/packages/toml.ts";
import { action, role } from "../types/auth.ts";

/** Advisory declarations never constrain the keys accepted by authorization. */
export async function declarations(
  root = new URL("file:///workspace/packages/"),
) {
  const files: URL[] = [];
  for await (const namespace of Deno.readDir(root)) {
    if (!namespace.isDirectory || namespace.name.startsWith(".")) continue;
    const owner = new URL(`${encodeURIComponent(namespace.name)}/`, root);
    for await (const pkg of Deno.readDir(owner)) {
      if (pkg.isDirectory && !pkg.name.startsWith(".")) {
        files.push(
          new URL(
            `${encodeURIComponent(pkg.name)}/declarations/auth.toml`,
            owner,
          ),
        );
      }
    }
  }
  const rows: { action: string; description: string }[] = [];
  for (let offset = 0; offset < files.length; offset += 32) {
    const batch = await Promise.all(
      files.slice(offset, offset + 32).map(async (file) => {
        try {
          if ((await Deno.stat(file)).size > 1 << 20) {
            throw new Error("Declaration exceeds 1 MiB");
          }
          return Object.entries(parse(await Deno.readTextFile(file))).map((
            [key, description],
          ) => ({
            action: action.parse(key),
            description: role.shape.description.parse(description),
          }));
        } catch (error) {
          if (!(error instanceof Deno.errors.NotFound)) {
            console.warn(
              `Cannot read authorization declarations ${file.pathname}: ${error}`,
            );
          }
          return [];
        }
      }),
    );
    rows.push(...batch.flat());
  }
  return rows.sort((a, b) =>
    a.action < b.action
      ? -1
      : a.action > b.action
      ? 1
      : a.description.localeCompare(b.description)
  );
}
