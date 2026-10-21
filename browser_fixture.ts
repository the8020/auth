import { assert, assertEquals } from "@std/assert";
import { authDatabase } from "./src/test_support.ts";

interface Browser {
  evaluate<T>(expression: string): Promise<T>;
  command(method: string, params?: Record<string, unknown>): Promise<unknown>;
}

export default async function fixture() {
  const database = await authDatabase();
  const users = await import("/p/the8020/users/src/admin.ts");
  const admin = await import("./src/admin.ts");
  const { check } = await import("./mod.ts");
  await users.add("tester");
  await users.add("alice");
  await admin.createRole({
    name: "tester",
    description: "Test administrator",
    permissions: { "*": "*" },
  });
  await admin.createRole({
    name: "sales",
    description: "Customer editors",
    permissions: { "sales.customer.*": "7000-9000,!8000-8200" },
  });
  database.asUser("alice");
  await check("sales.customer.edit", "7522");
  database.asUser("tester");
  const wait = async (
    page: Browser,
    expression: string,
    description: string,
  ) => {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      if (await page.evaluate<boolean>(expression)) return;
      await new Promise((resolve) => setTimeout(resolve, 30));
    }
    throw new Error(
      `Timed out: ${description}; ${await page.evaluate(
        "document.body.innerText",
      )}`,
    );
  };
  const visible =
    "item.getClientRects().length > 0 && !item.closest('[inert],[hidden]')";
  const button = (page: Browser, label: string) =>
    wait(
      page,
      `(() => { const item = [...document.querySelectorAll('button')].find(item => ${visible} && !item.disabled && (item.textContent.trim() === ${
        JSON.stringify(label)
      } || item.getAttribute('aria-label') === ${
        JSON.stringify(label)
      })); if (!item) return false; item.click(); return true; })()`,
      label,
    );
  const title = (page: Browser, name: string) =>
    wait(
      page,
      `[...document.querySelectorAll('.screen-title')].some(item => ${visible} && item.textContent.trim() === ${
        JSON.stringify(name)
      })`,
      name,
    );
  const input = async (page: Browser, bind: string, value: string) => {
    await wait(
      page,
      `(() => { const item = [...document.querySelectorAll('[data-bind="${bind}"]')].find(item => ${visible} && !item.disabled); if (!item) return false; item.value = ${
        JSON.stringify(value)
      }; item.dispatchEvent(new Event('input', { bubbles: true })); item.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`,
      bind,
    );
    await wait(
      page,
      "!document.querySelector('#screen-back')?.disabled",
      "input roundtrip",
    );
  };
  const row = (page: Browser, name: string) =>
    wait(
      page,
      `(() => { const item = [...document.querySelectorAll('.data-list tbody tr')].find(item => ${visible} && item.textContent.includes(${
        JSON.stringify(name)
      })); if (!item) return false; item.click(); return true; })()`,
      name,
    );
  return {
    async run() {
      const { default: program } = await import(
        "/p/the8020/users/programs/users/program.ts"
      );
      await program("alice");
      const { roles } = await import("./src/screens.ts");
      await roles();
    },
    serve(_request: Request) {
      return Promise.resolve(undefined);
    },
    close() {
      database.close();
      return Promise.resolve();
    },
    async verify(page: Browser) {
      await title(page, "User alice");
      await button(page, "Roles");
      await title(page, "Roles for alice");
      assertEquals(await admin.userRoles("alice"), []);
      await button(page, "Personal permissions");
      await title(page, "Role alice");
      assertEquals((await admin.getRole("alice")).permissions, {});
      await button(page, "Add permission");
      await title(page, "Permission · alice");
      await input(page, "action", "sales.customer.edit");
      await input(page, "values", "!<7000,!8000-8200");
      await wait(
        page,
        `(() => {
        const item = document.querySelector('input[data-bind="comparisons"]');
        if (!item || item.disabled) return false;
        if (!item.checked) item.click();
        return true;
      })()`,
        "enable comparisons",
      );
      await button(page, "Save permission");
      await title(page, "Role alice");
      assertEquals(
        (await admin.getRole("alice")).permissions["sales.customer.edit"],
        { comparisons: "!<7000,!8000-8200" },
      );
      await row(page, "sales.customer.edit");
      await title(page, "Permission · alice");
      await wait(
        page,
        `document.querySelector('input[data-bind="comparisons"]')?.checked === true`,
        "comparison mode survives reload",
      );
      await button(page, "Save permission");
      await title(page, "Role alice");
      await button(page, "Add permission");
      await title(page, "Permission · alice");
      await input(page, "action", "legacy.literal");
      await input(page, "values", ">10");
      await button(page, "Save permission");
      await title(page, "Role alice");
      await row(page, "legacy.literal");
      await title(page, "Permission · alice");
      await wait(
        page,
        `document.querySelector('input[data-bind="comparisons"]')?.checked === false`,
        "legacy mode survives reload",
      );
      await button(page, "Save permission");
      await title(page, "Role alice");
      assertEquals(
        (await admin.getRole("alice")).permissions["legacy.literal"],
        ">10",
      );
      const { verify } = await import("./mod.ts");
      assertEquals(await verify("alice", "legacy.literal", ">10"), true);
      assertEquals(await verify("alice", "legacy.literal", "11"), false);
      assertEquals(await verify("alice", "sales.customer.edit", "7000"), true);
      assertEquals(await verify("alice", "sales.customer.edit", "8100"), false);
      await button(page, "Included roles");
      await title(page, "Included roles · alice");
      await button(page, "Include role");
      await title(page, "Include role");
      await input(page, "value", "sales");
      await button(page, "Add");
      await title(page, "Included roles · alice");
      assertEquals(await admin.includedRoles("alice"), [{
        role: "alice",
        included: "sales",
      }]);
      await button(page, "Back");
      await title(page, "Role alice");
      await button(page, "Users");
      await title(page, "Users with alice");
      await row(page, "alice");
      await title(page, "alice · alice");
      await button(page, "Open user");
      await title(page, "User alice");
      await button(page, "Back");
      await title(page, "Users with alice");
      await button(page, "Back");
      await title(page, "Role alice");
      await button(page, "Back");
      await title(page, "Roles for alice");
      await button(page, "Assign role");
      await input(page, "value", "sales");
      await button(page, "Add");
      await title(page, "Roles for alice");
      assertEquals((await admin.userRoles("alice")).map((row) => row.role), [
        "alice",
        "sales",
      ]);
      await button(page, "Failed checks");
      await title(page, "Failed checks · alice");
      await row(page, "sales.customer.edit");
      await title(page, "Failed check");
      await wait(
        page,
        "[...document.querySelectorAll('textarea')].some(item => item.value.includes('missing_role'))",
        "failure evidence",
      );
      await button(page, "Back");
      await title(page, "Failed checks · alice");
      await page.command("Emulation.setDeviceMetricsOverride", {
        width: 390,
        height: 844,
        deviceScaleFactor: 1,
        mobile: true,
      });
      await wait(
        page,
        "document.documentElement.scrollWidth <= 390",
        "mobile width",
      );
      database.asUser("alice");
      assert(await check("sales.customer.edit", "7522"));
      assertEquals(await check("sales.customer.edit", "8100"), false);
      database.asUser("tester");
      await button(page, "Back");
      await title(page, "Roles for alice");
      await button(page, "Back");
      await title(page, "User alice");
      await button(page, "Back");
      await title(page, "Roles");
      await button(page, "Create role");
      await title(page, "Create role");
      await input(page, "name", "Regional Staff");
      await input(page, "description", "Regional customer editors");
      await button(page, "Save role");
      await title(page, "Role Regional Staff");
      assertEquals(
        (await admin.getRole("Regional Staff")).description,
        "Regional customer editors",
      );
      await button(page, "Delete role");
      await button(page, "Delete");
      await title(page, "Roles");
    },
  };
}
