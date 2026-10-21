import { AdminCommandError } from "@the8020/kernel";
import {
  parseCommandArguments,
  requiredCommandArgument,
} from "/p/the8020/packages/commands.ts";
import * as admin from "./admin.ts";

export async function command(operation: string, args: string[]) {
  const arg = (index: number, name: string) =>
    requiredCommandArgument(args, index, name);
  switch (operation) {
    case "create": {
      const parsed = parseCommandArguments(args, {
        values: ["description", "permissions"],
        booleans: ["if-missing"],
      });
      let permissions: unknown = {};
      try {
        permissions = JSON.parse(String(parsed.options.permissions ?? "{}"));
      } catch {
        throw new AdminCommandError({
          code: "invalid_arguments",
          message: "--permissions must be a JSON object",
        });
      }
      const { role } = await import("../types/auth.ts");
      return await admin.createRole(
        role.parse({
          name: requiredCommandArgument(parsed.positionals, 0, "role"),
          description: parsed.options.description ?? "",
          permissions,
        }),
        parsed.options["if-missing"] === true,
      );
    }
    case "list":
      return { roles: await admin.listRoles() };
    case "inspect":
      return {
        role: await admin.getRole(arg(0, "role")),
        includes: await admin.includedRoles(arg(0, "role")),
      };
    case "grant": {
      const parsed = parseCommandArguments(args.slice(3), {
        booleans: ["comparisons"],
      });
      const values = arg(2, "values");
      await admin.setPermission(
        arg(0, "role"),
        arg(1, "action"),
        parsed.options.comparisons === true ? { comparisons: values } : values,
      );
      break;
    }
    case "revoke":
      await admin.setPermission(arg(0, "role"), arg(1, "action"));
      break;
    case "delete": {
      const parsed = parseCommandArguments(args, { booleans: ["confirm"] });
      if (parsed.options.confirm !== true) {
        throw new AdminCommandError({
          code: "invalid_arguments",
          message: "role deletion requires --confirm",
        });
      }
      await admin.deleteRole(
        requiredCommandArgument(parsed.positionals, 0, "role"),
      );
      break;
    }
    case "assign":
    case "unassign":
      await admin.assignRole(
        arg(0, "username"),
        arg(1, "role"),
        operation === "assign",
      );
      break;
    case "include":
    case "exclude":
      await admin.includeRole(
        arg(0, "role"),
        arg(1, "included role"),
        operation === "include",
      );
      break;
    case "user-roles":
      return { roles: await admin.userRoles(arg(0, "username")) };
    case "role-users":
      return { users: await admin.roleUsers(arg(0, "role")) };
    case "personal":
      return { role: await admin.personalRole(arg(0, "username")) };
    case "failures":
      return { failures: await admin.failedChecks(args[0]) };
    default:
      throw new AdminCommandError({
        code: "invalid_arguments",
        message: "Unknown authorization command",
      });
  }
  return { success: true };
}
