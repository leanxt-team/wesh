---
name: wesh-spec-back
description: Enrich WeshCraft back specs (specs/back/*.md) from a FigCraft prototype: validation, authz, errors, data, open questions. Never invents endpoints. Use for "enrich/complete back spec".
---

Entities, fields and operations are derived from the prototype (explicit bindings and annotations, or inferred from repeated components and action labels) and contract-checked. Do not add, rename or drop them in prose. You write only the Notes block (`weshcraft_notes`).


Read `specs/FUNCTIONS.md` first: an operation's function (and the data it reads and writes) frames its validation, authorization and errors.
Rules (`specs/LOGIC.md`), entities and relations (`specs/DATA.md`) and components (`specs/ARCHITECTURE.md`) frame validation, transitions, authorization and where the code goes.
Existing code for an operation or entity: `weshcraft_read {what:"trace"}` (or `specs/TRACE.md`) lists what is tagged `@weshcraft METHOD /path` or `@weshcraft Entity`; `codegraph_explore "<METHOD /path> handler"` shows it with callers. Name the file you would extend.

## Read first
`specs/back/domain.md`, `api.md`, `openapi.json`, `conventions.md`, the public API and MCP specs under `specs/front/api` and `specs/front/mcp` when present, `specs/LINKS.md` (or `weshcraft_read {what:"links"}`): which layers trigger, submit to and show each operation's data; the screens each operation cites. Existing back-end code: models, routes, auth, validation library, error format, migrations. Reuse them; name the file you would extend.

## Write, only what applies
- `### Validation`: per request field (its input `#id`): required, type, length, format, server-side rule, error message the screen shows.
- `### Auth and permissions`: who may call each operation; ownership checks (object-level authorization) for every id in a path.
- `### Errors`: each failure mapped to status + `code` from conventions, and to the layer that shows it (the triggering or submitting `#id` from the links).
- `### Data`: per entity: source of truth, uniqueness, indexes the lists need (sort/filter from the screen), retention, personal data and its basis, deletion.
- `### Consistency`: idempotency for writes, concurrent edits, transactions spanning entities, events emitted.
- `### Performance`: list sizes the screens imply, pagination, caching, N+1 risks.
- `### Mapping to existing code`: `path:line` of models/routes to extend, or "new".
- `### Open questions`: numbered, recommended answer each. Inferred (`confidence: inferred`) items always appear here until confirmed; recommend confirming them in the design (`{{entity.field}}` binding or a `METHOD /path` annotation), not in prose.

## Rules
- Never invent an endpoint or field. Needed and missing: open question + the design change that would add it.
- Never-cut list applies: validation at the trust boundary, authz, error handling, migration safety.
- Under 60 lines per spec. No preamble.
