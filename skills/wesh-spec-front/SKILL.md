---
name: wesh-spec-front
description: Enrich WeshCraft front specs (specs/front/*.md) from a FigCraft prototype: states, a11y, analytics, open questions. Never changes generated facts. Use for "enrich/complete front spec".
---

Spec facts (layout, copy, typography, colours, interactions, components, sizes) are generated from the prototype and contract-checked. Do not restate, reword or "fix" them. You write only the Notes block (`weshcraft_write_notes`, or between the `weshcraft:notes` markers when editing files).


Read the screen's function in `specs/FUNCTIONS.md` first: its purpose frames the screen's states, empty cases and acceptance criteria.
Existing code for the screen: `weshcraft_trace` (or `specs/TRACE.md`) lists what is tagged `@weshcraft <key>`; `codegraph_explore "<screen name> screen"` shows it with its calls. Notes that name code cite `file:symbol`.

## Read first
The spec (`weshcraft_read_spec`), the screens it links, `weshcraft_manifest {screen}` for ids. Existing code for the same screen or component, when the repo has it: match its patterns.

## Write, only what applies, under these headings
- `### States`: loading, empty, error, disabled, offline, permission denied, long content (copy 2× longer, 1 item, 0 items, 1 000 items). Tie each to its back-end link from §Front ⇄ back links: loading/empty/error of the operation that loads a ◉ field or fills a ☰ list; pending/failure of the operation a ▶ layer triggers. Say what the prototype shows; where it shows nothing, it is an open question, not your invention.
- `### Interaction details`: focus order through the cited `#id`s, keyboard (Enter/Space on every clickable, Esc closes overlays, Back), pointer vs touch targets (≥ 44 px), double submit, transition from §Interactions honoured with `prefers-reduced-motion`.
- `### Accessibility`: accessible name for each interactive `#id` (from its visible text), headings order, images: decorative or alt text, contrast rows flagged ⚠️ in §Copy.
- `### Responsive`: behaviour outside the designed frame width, from auto layout sizing (fill/hug/fixed) in §Layout.
- `### Analytics`: one event per user decision (`screen_viewed`, `<action>_clicked`), properties, no personal data.
- `### Open questions`: numbered, each with a recommended answer; prefer "add a state/frame in FigCraft" over prose decisions.

## MCP tools and API endpoints (specs/front/mcp, specs/front/api)
The user is an agent (tools) or a developer (endpoints). Write, when they apply:
- `### When to use`: the situations an agent should pick this tool, and the near-miss tools it should not be confused with.
- `### Errors`: each failure as the tool result / status + body the caller gets, worded so an agent can recover.
- `### Safety`: confirmation needed (destructive), side effects outside the service (open world), rate limits, idempotency keys.
- `### Compatibility`: what would break callers (renames, new required arguments, enum changes); versioning.
Never contradict the schema or annotations; to change them, change the server or the OpenAPI document.

## Rules
- Cite layers as `#id` in backticks, only ids present in the spec. No new copy, colours or sizes: those come from the design.
- Under 60 lines per spec. No preamble, no summary of the tables.
- Something wrong in the facts (a missing state, a bad contrast): say so in Open questions; the fix is a design edit, then regeneration.
