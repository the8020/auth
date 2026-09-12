import { command } from "../../src/commands.ts";
export default function run(...args: string[]) {
  return command("delete", args);
}
