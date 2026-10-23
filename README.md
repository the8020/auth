# 80|20 authorization

Database roles provide additive application permissions. Checks use the trusted
execution user; `system` bypasses them. Other users automatically receive their
username role when it exists, plus explicit assignments and included roles.

```ts
import { check, requirePermission } from "/p/the8020/auth/mod.ts";

await requirePermission("sales.customer.edit", "7522");
const allowed = await check("sales.customer.view", "7522");
```

`check` and `requirePermission` keep the trusted execution principal and write
one failure record per denial. The read-only helpers below never write those
records:

```ts
import { filter, sqlPredicate, verify } from "/p/the8020/auth/mod.ts";

const allowed = await verify("alice", "sales.customer.view", "7522");
const visible = await filter("alice", [
  { customer: "7522", region: "EU" },
  { customer: "8100", region: "US" },
], {
  customer: "sales.customer.view",
  region: "sales.region.view",
});
// Each key is an own record property; its value is the scalar action to check.
// Both checks must pass. Independent roles/entries can satisfy each check.

const predicate = await sqlPredicate(
  "alice",
  "sales.customer.view",
  "customer.number",
);
// With your existing Kysely customer query:
const rows = await customerQuery.where(predicate).execute();
```

Explicit identities are **usernames**, such as `alice`, not `user:alice` IDs.
Unknown accounts deny, even if an orphaned username role exists. `system`
retains its explicit bypass. These are permission queries, not authentication or
a way to replace the trusted principal of existing enforcement calls:
application callers must choose the identity from their trusted context.
Existing trusted service principals can still use `check` without a
users-package account. Password and account eligibility policy stays with
authentication.

For menus and tiles, `permittedActions(username, actions)` returns a `Set` of
actions granted for some value, loading the roles once for the entire batch.
`permitsAny(username, action)` checks a single action by the same rule. These
helpers do not audit; the program still enforces permission for its actual
value.

`filter` returns a new array in input order and retains the original objects. It
requires a nonempty property-to-action mapping and ANDs the checks. Missing,
inherited, null, non-string, or overlong properties fail; values are not
coerced. Auth currently has independent scalar grants, not correlated
multi-field grants. The SQL helper represents **one scalar action/value check
only**; callers needing several checks must AND their predicates. It cannot
project a hypothetical correlated multi-field policy onto one field.

`sqlPredicate` returns a Kysely `RawBuilder<SqlBool>` for `.where()`
composition. It accepts a qualified reference string (quoted by `sql.ref`) or a
typed Kysely text expression, and binds every permission value. Empty grants
produce `false`, never an omitted restriction. PostgreSQL and SQLite text fields
are supported, including nullable text; nulls deny, including for `system`. Use
well-formed Unicode text without NUL, the common PostgreSQL/SQLite text domain.
SQL permission values outside this domain throw; SQLite NUL data denies. Numeric
SQL columns are outside this API: use a text-valued field with the same
representation you pass to `verify`, rather than relying on database coercion.
SQLite non-text values deny; PostgreSQL incompatible expressions may throw.
String length is limited to 2048 UTF-16 units across helpers, as in `check`.

All helpers traverse reachable roles once per invocation, compile matching
entries once, and keep exclusions local to each entry. No cross-call cache
exists; permission edits take effect on the next invocation. The full traversal
must fit the existing role cap even when an early role grants. SQL predicates
capture the permissions at construction time: construct them for each operation,
rather than retaining them after edits. Comparisons use exact decimal text and
deterministic case-sensitive ordering on both databases, without a database
extension or UDF. Unicode ordering/length may require bounded character scans;
predicates are not guaranteed to use an index. Database query/parameter limits
and operational errors propagate; they never fall back to unrestricted access.

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
`?` one character. String values support comma-separated exact values, inclusive
numeric or lexical ranges, and `!` exclusions. The example excludes **8000
through 8200**; use `!8200` for one value. Escape punctuation with backslash for
literals, such as `foo\-bar` or `a\,b`. Numeric ranges compare exact signed
decimals. At least one positive term must match; exceptions affect only their
own permission entry. Another entry or role can grant access, including the
personal `8100` grant above.

Comparisons require an explicit per-entry opt-in. Existing stored strings keep
their original meaning: `>10` is a literal, `!>10` is an exclusion that grants
nothing alone, and `>-~` is an inclusive lexical range. No existing permission
is reinterpreted or migrated. Enable **Comparisons** in the permission editor,
or put `--comparisons` after the command's three positional arguments:

```sh
auth.roles.grant sales 'sales.customer.view' '>=7000,!8000-8200' --comparisons
```

The API and stored JSON use a distinct object for that entry:

```ts
import { setPermission } from "/p/the8020/auth/src/admin.ts";

await setPermission("sales", "sales.customer.view", {
  comparisons: ">=7000,!8000-8200",
});
// Role permissions: { "sales.customer.view": { comparisons: ">=7000,!8000-8200" } }
```

`PermissionValues`, exported from `mod.ts`, is
`string | { comparisons: string }`. Both forms use the existing JSON column; no
database schema change is needed. Plain strings passed to existing APIs or
commands retain the original grammar. The editor displays and preserves each
entry's mode, including when saving an existing entry without changing it.
Changing that mode explicitly changes how the entry is interpreted.

## Attribute values on assignments

One role can serve any channel, state or company: its entry refers to an
**attribute**, and each assignment supplies that attribute's values. Declare
attributes next to actions in `declarations/auth-attributes.toml`:

```toml
"dlis.einvoice.channel" = "eInvoice channel code (SK, DE, FR); empty value means documents without a channel."
```

Reference the attribute in a role entry and give values when assigning:

```sh
auth.roles.create dlis.einvoice.viewer
auth.roles.grant dlis.einvoice.viewer dlis.einvoice.documents.view dlis.einvoice.channel --attribute
auth.users.assign novak dlis.einvoice.viewer --attribute dlis.einvoice.channel=SK,CZ
# Comparisons for one attribute: --attribute-comparisons dlis.einvoice.limit=<=10000
```

Stored entries are `{ attribute: "dlis.einvoice.channel" }`; assignment values
use the ordinary value grammar or `{ comparisons }`. Roles included by the
assigned role use the same values. Values stay with their assignment: a user who
approves `SK` through one assignment and only views `CZ` through another cannot
approve `CZ`. An attribute without a value on the assignment grants nothing.
Repeating `auth.users.assign` with attributes replaces them; without attributes
it keeps them. In **Roles for <user>**, open an assignment and choose
**Attribute values**; assigning a role that refers to attributes opens that
editor directly.

For menus and tiles, `permitsAny(username, action)` answers whether the user can
perform the action for at least one value, without writing an audit record.

In comparison mode, use `>10`, `>=10`, `<10`, or `<=10`. The convenience forms
`!>10`, `!>=10`, `!<10`, and `!<=10` normalize to `<=10`, `<10`, `>=10`, and
`>10`. They are **positive grants**, even on their own; `*,!>10` therefore still
grants all strings. Use `<=10` directly for that upper bound. To exclude an
exact value or inclusive range, keep `!10` or `!10-20`. For example,
`>=7000,!8000-8200` grants at least 7000 except the inclusive excluded interval.

If the comparison endpoint is a signed decimal, only strings matching
`-?digits[.digits]` are ordered, with exact precision (including leading zeros
and negative zero). Exponent notation, plus signs, whitespace, and other text do
not match numeric comparisons, including negated aliases. Other endpoints use
the existing JavaScript UTF-16 lexical order, case-sensitively; empty strings
are ordered lexically and match `*`. Bounded ranges still include both endpoints
and are numeric only when both endpoints are numeric. Comparisons never coerce
null or missing values into strings: `verify`/`check` reject invalid scalar
arguments, while filtering and SQL deny invalid row values. In comparison mode,
escape leading comparison punctuation for literals, for example `\>10` or
`\!>10`. The permission editor uses this same parser and shows the grammar in
field help.

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
authority. Docker bootstrap assigns the new administrator the managed role
`the8020.users.administrator` (`"*" = "*"`), falling back to a role `**` with
the same permission on older users packages. For an existing deployment, assign
the role through the native administrator console, replacing `admin` with its
username:

```sh
auth.users.assign admin the8020.users.administrator
```

Package-declared roles (`declarations/auth-roles.toml`), assignment attributes,
Home tile visibility and the success audit with its retention are described in
the [DOX contract](AGENTS.md).

Run `deno task check`, `deno task test`, and `deno task test:browser` from this
repository. `deno task test:postgres` additionally executes the shared
comparison fixtures through `psql`; configure its ordinary `PGHOST`, `PGPORT`,
`PGUSER`, and `PGDATABASE` for an isolated test database. It uses a temporary
table and rolls back; credentials need not appear in source or arguments. The
standard test task skips this opt-in check. Permission loading is exercised
through the SQLite bridge; the PostgreSQL check executes the production
predicate compiler's output against PostgreSQL. The browser check reuses the
sibling UUI Chromium harness. The [DOX contract](AGENTS.md) records API
ownership and resource limits.

## Package-declared roles

Packages ship their roles in `declarations/auth-roles.toml`, named with the
package prefix (`dlis/einvoice` → `dlis.einvoice.`):

```toml
["dlis.einvoice.viewer"]
description = "View documents and their log in your channels."
permissions = { "dlis.einvoice.documents.view" = { attribute = "dlis.einvoice.channel" } }

["dlis.einvoice.user"]
description = "eInvoice channel user."
collection = true
includes = ["dlis.einvoice.viewer", "dlis.einvoice.approver"]
```

Activating the package creates or updates these roles; no hook code or private
auth import is needed. They show **Managed by** in Roles and cannot be edited
there: assign them, include them in your own collections, or use **Copy role**.
A copy is an ordinary role that remembers its template; its **Changes in the
template** list shows what the package has added, removed or changed since, and
**Adopt template changes** takes them over. From the command line:

```sh
auth.roles.copy dlis.einvoice.user my-einvoice-user
auth.roles.changes my-einvoice-user
auth.roles.adopt my-einvoice-user
```

A role the package stops declaring is kept as **Obsolete** while users or roles
still use it, and removed once unused.
