# 80|20 authorization

Database roles provide additive application permissions. Checks use the trusted
execution user; `system` bypasses them. Other users automatically receive their
username role when it exists, plus explicit assignments and included roles.

```ts
import { check, requirePermission } from "/p/the8020/auth/mod.ts";

await requirePermission("sales.customer.edit", "7522");
const allowed = await check("sales.customer.view", "7522");
```

Use the administration command bus to create and assign roles:

```sh
auth.roles.create sales --description 'Customer editors'
auth.roles.grant sales 'sales.customer.*' '7000-9000,25*,4444,3333,!8000-8200,!2577'
auth.users.assign alice sales
auth.roles.create staff
auth.roles.include staff sales
auth.users.personal alice
auth.roles.grant alice 'sales.customer.edit' '8100'
auth.failures.list alice
```

Patterns match the complete case-sensitive string. `*` matches any sequence and
`?` one character. Values support comma-separated exact values, inclusive
numeric or lexical ranges, and `!` exclusions. The example excludes **8000
through 8200**; use `!8200` for one value. Escape punctuation with backslash for
literals, such as `foo\-bar` or `a\,b`. Numeric ranges compare exact signed
decimals. At least one positive term must match; exceptions affect only their
own permission entry. Another entry or role can grant access, including the
personal `8100` grant above.

The **Roles** and **Failed authorization checks** programs appear on Home. User
details link to assigned roles; roles link to users and included roles. Personal
roles are created only when editing permissions. The auth package subscribes to
`users.deleted` and removes the username role and all associated assignments and
inclusions in its own transaction. User deletion itself touches only users-owned
records.

Publish advisory authorization keys in each package's `declarations/auth.toml`:

```toml
"sales.customer.edit" = "Edit a customer; value is the customer number."
"sales.customer.view" = "View a customer; value is the customer number."
```

Action value help reads installed declarations on demand and sorts by key. Keys
remain free-form. Publishers similarly document custom events in
`declarations/events.toml`, including payload and timing; subscriptions continue
to use ordinary `events/*.toml` declarations. See
[users' published events](../users/declarations/events.toml).

The first protected application APIs are user, service, and package mutations.
Native operations and uninstrumented applications retain their existing
authority. Docker bootstrap creates role `**`, grants `"*" = "*"`, and assigns
it to the new administrator. For an existing deployment, run the same commands
through the native administrator console, replacing `admin` with its username:

```sh
auth.roles.create '**' --if-missing
auth.roles.grant '**' '*' '*'
auth.users.assign admin '**'
```

Run `deno task check`, `deno task test`, and `deno task test:browser` from this
repository. The browser check reuses the sibling UUI Chromium harness. The
[DOX contract](AGENTS.md) records API ownership and resource limits.
