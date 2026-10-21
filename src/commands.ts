import { AdminCommandError } from "@the8020/kernel";
import {
  parseCommandArguments,
  requiredCommandArgument,
} from "/p/the8020/packages/commands.ts";
import * as admin from "./admin.ts";
import * as audit from "./audit.ts";

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
        booleans: ["comparisons", "attribute"],
      });
      const values = arg(2, "values");
      if (
        parsed.options.comparisons === true && parsed.options.attribute === true
      ) {
        throw new AdminCommandError({
          code: "invalid_arguments",
          message: "--comparisons and --attribute are mutually exclusive",
        });
      }
      await admin.setPermission(
        arg(0, "role"),
        arg(1, "action"),
        parsed.options.attribute === true
          ? { attribute: values }
          : parsed.options.comparisons === true
          ? { comparisons: values }
          : values,
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
    case "assign": {
      const { positionals, attributes } = assignmentArguments(args);
      await admin.assignRole(
        requiredCommandArgument(positionals, 0, "username"),
        requiredCommandArgument(positionals, 1, "role"),
        true,
        attributes,
      );
      break;
    }
    case "unassign":
      await admin.assignRole(arg(0, "username"), arg(1, "role"), false);
      break;
    case "include":
    case "exclude":
      await admin.includeRole(
        arg(0, "role"),
        arg(1, "included role"),
        operation === "include",
      );
      break;
    case "copy":
      return {
        role: await admin.copyRole(arg(0, "role"), arg(1, "new role")),
      };
    case "adopt":
      await admin.adoptTemplate(arg(0, "role"));
      break;
    case "changes":
      return await admin.templateChanges(arg(0, "role"));
    case "user-roles":
      return { roles: await admin.userRoles(arg(0, "username")) };
    case "role-users":
      return { users: await admin.roleUsers(arg(0, "role")) };
    case "personal":
      return { role: await admin.personalRole(arg(0, "username")) };
    case "failures":
      return { failures: await admin.failedChecks(args[0]) };
    case "audit":
      return { grants: await audit.grantedChecks(args[0]) };
    case "retention": {
      if (
        args.length > 1 || args[0] !== undefined && !/^[0-9]+$/.test(args[0])
      ) {
        throw new AdminCommandError({
          code: "invalid_arguments",
          message: "usage: [days]",
        });
      }
      return {
        days: args[0] === undefined
          ? await audit.auditRetention()
          : await audit.setAuditRetention(Number(args[0])),
      };
    }
    default:
      throw new AdminCommandError({
        code: "invalid_arguments",
        message: "Unknown authorization command",
      });
  }
  return { success: true };
}

/**
 * `--attribute name=values` may repeat; `--attribute-comparisons name=values`
 * enables comparison operators for that attribute's values.
 */
function assignmentArguments(args: readonly string[]) {
  const positionals: string[] = [];
  let attributes: Record<string, string | { comparisons: string }> | undefined;
  for (let index = 0; index < args.length; index++) {
    const token = args[index]!;
    const option = ["--attribute", "--attribute-comparisons"].find((name) =>
      token === name || token.startsWith(`${name}=`)
    );
    if (option === undefined) {
      positionals.push(token);
      continue;
    }
    const pair = token === option
      ? args[++index]
      : token.slice(option.length + 1);
    const separator = pair?.indexOf("=") ?? -1;
    if (pair === undefined || separator <= 0) {
      throw new AdminCommandError({
        code: "invalid_arguments",
        message: `${option} requires name=values`,
      });
    }
    const name = pair.slice(0, separator);
    const values = pair.slice(separator + 1);
    attributes ??= {};
    if (Object.hasOwn(attributes, name)) {
      throw new AdminCommandError({
        code: "invalid_arguments",
        message: `repeated attribute ${name}`,
      });
    }
    attributes[name] = option === "--attribute"
      ? values
      : { comparisons: values };
  }
  return { positionals, attributes };
}
