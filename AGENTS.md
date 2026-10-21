Parent DOX: [8020 workspace](../AGENTS.md).

Framework source:
[agent0ai/dox/AGENTS.md](https://github.com/agent0ai/dox/blob/765ae4ac02cc884eefcd41a3d0f71941721adb89/AGENTS.md).

# DOX framework

- DOX is highly performant AGENTS.md hierarchy installed here
- Agent must follow DOX instructions across any edits

## Core Contract

- AGENTS.md files are binding work contracts for their subtrees
- Work products, source materials, instructions, records, assets, and durable
  docs must stay understandable from the nearest applicable AGENTS.md plus every
  parent AGENTS.md above it

## Read Before Editing

1. Read the root AGENTS.md
2. Identify every file or folder you expect to touch
3. Walk from the repository root to each target path
4. Read every AGENTS.md found along each route
5. If a parent AGENTS.md lists a child AGENTS.md whose scope contains the path,
   read that child and continue from there
6. Use the nearest AGENTS.md as the local contract and parent docs for repo-wide
   rules
7. If docs conflict, the closer doc controls local work details, but no child
   doc may weaken DOX

Do not rely on memory. Re-read the applicable DOX chain in the current session
before editing.

## Update After Editing

Every meaningful change requires a DOX pass before the task is done.

Update the closest owning AGENTS.md when a change affects:

- purpose, scope, ownership, or responsibilities
- durable structure, contracts, workflows, or operating rules
- required inputs, outputs, permissions, constraints, side effects, or artifacts
- user preferences about behavior, communication, process, organization, or
  quality
- AGENTS.md creation, deletion, move, rename, or index contents

Update parent docs when parent-level structure, ownership, workflow, or child
index changes. Update child docs when parent changes alter local rules. Remove
stale or contradictory text immediately. Small edits that do not change behavior
or contracts may leave docs unchanged, but the DOX pass still must happen.

## Hierarchy

- Root AGENTS.md is the DOX rail: project-wide instructions, global preferences,
  durable workflow rules, and the top-level Child DOX Index
- Child AGENTS.md files own domain-specific instructions and their own Child DOX
  Index
- Each parent explains what its direct children cover and what stays owned by
  the parent
- The closer a doc is to the work, the more specific and practical it must be

## Child Doc Shape

- Create a child AGENTS.md when a folder becomes a durable boundary with its own
  purpose, rules, responsibilities, workflow, materials, or quality standards
- Work Guidance must reflect the current standards of the project or user
  instructions; if there are no specific standards or instructions yet, leave it
  empty
- Verification must reflect an existing check; if no verification framework
  exists yet, leave it empty and update it when one exists

Default section order:

- Purpose
- Ownership
- Local Contracts
- Work Guidance
- Verification
- Child DOX Index

## Style

- Keep docs concise, current, and operational
- Document stable contracts, not diary entries
- Put broad rules in parent docs and concrete details in child docs
- Prefer direct bullets with explicit names
- Do not duplicate rules across many files unless each scope needs a local
  version
- Delete stale notes instead of explaining history
- Trim obvious statements, repeated rules, misplaced detail, and warnings for
  risks that no longer exist

## Closeout

1. Re-check changed paths against the DOX chain
2. Update nearest owning docs and any affected parents or children
3. Refresh every affected Child DOX Index
4. Remove stale or contradictory text
5. Run existing verification when relevant
6. Report any docs intentionally left unchanged and why

## User Preferences

When the user requests a durable behavior change, record it here or in the
relevant child AGENTS.md

## Child DOX Index

This root owns all package sources, schemas, declarations, programs, and checks.
No child DOX documents.

# Purpose

- Own application authorization through database roles for `the8020/auth`.

# Ownership

- `widgets/` declares this package's Home tiles and categories through the
  `the8020/packages/widgets.ts` format.
- `mod.ts` exposes enforcement, verification, array filtering and SQL
  predicates; `src/` owns shared parsing/evaluation, role operations,
  declaration discovery, commands, and screens. `types/` owns shared semantic
  fields.
- `tables/` owns roles, nested role links, user assignments, and denied checks.
- `programs/` and `cbus/commands/` expose ordinary management entrypoints.
- `events/` subscribes to user deletion; auth owns cleanup of its role data.
- Kernel principals and authentication remain with their existing owners.

# Local Contracts

- Role, permission, inclusion, and assignment creation plus list refresh/paging
  live in their owning list toolbars. Entity navigation, edits, and confirmation
  actions stay in screen headers.

- `check(action, value)` returns a boolean; `requirePermission(action, value)`
  throws `AuthorizationError` with code `forbidden`. Inputs are strings; no API
  parameter can replace the trusted checking user. Anonymous services use their
  configured principal, including the explicit system bypass; trusted principals
  need not have users-package account rows.
- `verify(username, action, value)`, `filter(username, rows, mapping)` and
  `sqlPredicate(username, action, field)` are unaudited permission queries with
  explicit usernames, not `user:<name>` IDs or authentication. Unknown accounts
  deny even if orphan roles exist; `system` bypasses permission lookup. Callers
  own identity selection from trusted context. Keep enforcement callers on
  `check`/`requirePermission`.
- Array mapping keys are own properties and values are scalar action names; all
  mapped checks must pass. Require a nonempty mapping, preserve object identity
  and order in a new array, and deny missing/non-string/overlong values. Grants
  are independent across scalar checks; no correlated multi-field model exists.
- SQL returns a bound Kysely boolean expression for one scalar action and a text
  reference/expression. Empty grants return false. PostgreSQL and SQLite share
  exact decimal, case-sensitive pattern and UTF-16 lexical semantics. Restrict
  SQL to well-formed Unicode text without NUL: invalid permission text throws,
  SQLite NUL/non-text rows deny, and null/overlong text rows deny on both
  engines. Do not coerce numeric columns. Compose multiple scalar predicates
  with AND; never flatten correlated policies if such a model is added later.
- `src/evaluation.ts` owns bounded role aggregation and evaluation for every
  helper. Load once per invocation/batch, parse each entry once, preserve local
  exclusions and propagate operational errors. SQL captures grants at creation;
  reconstruct for each operation. No persistent cache, schema migration, UDF, or
  new dependency. Query engine limits propagate and never remove restrictions.
- `events/user-deleted.toml` subscribes to `users.deleted` with the ordinary
  `the8020/auth/user-deleted` program. It validates the event payload and calls
  auth-owned cleanup in an auth transaction, removing that user's assignments,
  its username role, other users' assignments to that role, and
  incoming/outgoing inclusions. Cleanup tolerates absent roles/links and
  repeated delivery. The users package never calls auth cleanup or deletes auth
  records.
- Assignment locks the account before the role; role deletion and event cleanup
  lock the role. Nested links lock role names in sorted order.
- Role names are literal even for `*` or `**`. Numeric ranges compare exact
  signed decimals without floating-point rounding; other ranges use lexical,
  case-sensitive ordering. Bounds are inclusive. `!8200` excludes one value;
  `!8000-8200` excludes the complete range. Negative-only expressions grant
  nothing. Escape comma, hyphen, star, question mark, exclamation, and backslash
  when needed for literals. Empty checked values match `*`.
- Stored permission strings retain the original grammar, including literal
  `<`/`>` prefixes, `!>10` exclusions and lexical ranges such as `>-~`. The
  explicit per-entry object `{ comparisons: string }` enables comparisons in the
  existing JSON column; never infer a mode from string contents or silently
  convert existing entries. `PermissionValues` is exported from `mod.ts`.
  `setPermission` and role creation/save accept both forms. The grant command
  opts in with `--comparisons` after its three positional arguments; without it,
  strings retain legacy semantics. The editor's Comparisons checkbox and list
  column preserve and display each entry's mode. Description edits and unrelated
  grants must not convert entries. No data/schema migration is needed.
- In comparison mode, `>`, `>=`, `<`, `<=` compare one literal endpoint. `!>`,
  `!>=`, `!<`, `!<=` normalize to positive `<=`, `<`, `>=`, `>` grants in the
  shared parser; they are not exclusions. Numeric endpoints accept only exact
  signed decimal strings, never null, exponent notation or coercion. Other
  endpoints use case-sensitive UTF-16 order. Escape leading comparison
  punctuation for a literal. Existing inclusive ranges and `!value`/`!range`
  exclusions remain. Permission entry/display uses `types/auth.ts` and the
  shared parser.
- Maximums: names 200 characters, actions 512, checked values 2048, expressions
  8192, and 256 permission entries per role. Walk at most 10,000 reachable roles
  in batches of 100; a complete traversal must fit the limit even if an early
  entry grants. Exceeding it denies; enforcement records `role_limit`. Denials
  retain at most 100 diagnostic entries. No successful-check history or
  cross-check permission cache exists.
- `auth.roles.*` commands manage roles/entries/inclusions; `auth.users.*` manage
  assignments/personal roles; `auth.failures.list` reads the latest 100 denials.
  `create --if-missing` preserves an existing role. Assignment/inclusion edits
  require authority over both the target and the granted role.
- Public UI programs are `roles`, `user-roles(username)`, and
  `failures(username?)`. Keep blank drafts optional with ordinary Zod wrappers;
  validate required fields before saving. Roles and relationship reads are
  bounded to 1000 rows; failure history pages 100 rows. Semantic role value help
  uses SQL filtering and paging.
- This is opt-in application authorization. The initial consumers are users,
  services, and package mutation owners. It does not restrict native recovery,
  arbitrary installed code, database administration, or uninstrumented programs.

- Check the trusted execution username. `system` bypasses checks. Other users
  start with their username role plus explicit assignments; absent roles grant
  nothing. Nested roles are additive and visited once, including cycles.
- Roles have literal, case-sensitive names and a map of action patterns to value
  expressions. Each matching entry grants independently; exclusions apply only
  inside that entry. No role can override another role's grant.
- Checks use one scalar string. Patterns match the complete case-sensitive text;
  `*` matches any sequence and `?` one character. Backslash escapes punctuation.
  Value expressions contain comma-separated exact values, patterns, inclusive
  numeric or lexical ranges, and `!` exclusions. At least one positive match is
  required. Escape a literal hyphen when it could denote a range.
- Failed enforcement checks persist username, action, value, UTC time, reason,
  and bounded evaluation details. Operational failures propagate and never grant
  access.
- Create username roles lazily on personal-permission edits. Role management
  requires authorization and all mutations share `src/admin.ts`.
- `declarations/auth.toml` maps quoted action IDs to descriptions. It is
  advisory; free-form actions remain valid. Read installed package declarations
  on demand in bounded concurrent batches and sort by action for ordinary UUI
  value help.
- Management uses owner-defined fields, normal UUI screens, and bidirectional
  user/role navigation. No browser components or authorization runtime exist.

# Work Guidance

- Package versions use annotated numeric Git tags; `package.toml` has no version
  field. Record release notes and compatibility limits in the tag annotation.

- Build only what the request and established contracts require. Before adding a
  mechanism, identify that need and why existing owners or standard tools cannot
  meet it. Do not invent stronger guarantees for hypothetical cases. Remove
  unsupported additions at closeout; agent-written tests and DOX do not
  authorize them. Preserve required correctness, security, and data integrity.

- Keep checks at application mutation owners. Reuse Kysely, Zod, TOML, and UUI.
- Use bounded queries and cycle-safe traversal without permission caches.

## UI Rules

- Do not add explanatory helper copy that restates what the control already
  implies (e.g. "optional", "works without selection", "failure falls back to
  X"). Prefer clear labels and option text; surface status in results when
  needed, not as instructional paragraphs under every field.
- Keep UI copy concise. Avoid tutorial-style descriptions unless the user
  explicitly asks for onboarding help.

# Verification

- Run package tasks inside an 80|20 Deno workspace; its root config supplies
  platform imports. The package config owns dependencies and tasks.

- `deno task test:browser` uses the existing UUI Chromium harness with real
  screens and SQLite, covering user-role navigation, lazy personal roles,
  permission edits, inclusions, assignments, failed-check evidence, and mobile
  sizing. `browser_fixture.ts` and `src/test_support.ts` are test-only adapters.
- Cross-package checks cover rejected service/package mutations before native
  calls, immediate grant/revoke behavior, event-owned user-deletion cleanup, and
  command parsing. Verify that user deletion leaves auth records for the
  listener and that repeated delivery is harmless. The kernel Docker entrypoint
  test owns resumed administrator grants.

- `deno task check` formats, lints, and checks source types.
- `deno task test` checks matching and SQLite-backed role/check operations,
  helper parity, query counts, non-mutation, audit counts, limits and injection
  boundaries, plus raw legacy grants and explicit comparison-mode edits.
- `deno task test:postgres` uses `psql` with standard `PG*` environment settings
  against an isolated test database. It executes production-generated predicates
  with bound parameters and shared verify/filter cases in temporary tables, then
  rolls back. Permission aggregation uses the SQLite bridge in this check. The
  fixtures include raw legacy strings without conversion. The ordinary test task
  skips the opt-in PostgreSQL test.
- `README.md` owns concise API examples, scalar mapping semantics, comparison
  boundaries and SQL text/type constraints. No parent DOX structure changes are
  needed when adding ordinary source/test files here.
