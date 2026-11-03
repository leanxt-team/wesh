---
name: wesh-spec-front
description: Enrich WeshCraft front specs (specs/front/*.md) from a FigCraft prototype: states, a11y, analytics, open questions. Never changes generated facts. Use for "enrich/complete front spec".
---

Spec facts (layout, copy, typography, colours, interactions, components, sizes) are generated from the prototype and contract-checked. Do not restate, reword or "fix" them. You write only the Notes block (`weshcraft_write_notes`, or between the `weshcraft:notes` markers when editing files).

## Read first
The spec (`weshcraft_read_spec`), the screens it links, `weshcraft_manifest {screen}` for ids. Existing code for the same screen or component, when the repo has it: match its patterns.

## Write, only what applies, under these headings
- `### States`: loading, empty, error, disabled, offline, permission denied, long content (copy 2× longer, 1 item, 0 items, 1 000 items). Say what the prototype shows; where it shows nothing, it is an open question, not your invention.
- `### Interaction details`: focus order through the cited `#id`s, keyboard (Enter/Space on every clickable, Esc closes overlays, Back), pointer vs touch targets (≥ 44 px), double submit, transition from §Interactions honoured with `prefers-reduced-motion`.
- `### Accessibility`: accessible name for each interactive `#id` (from its visible text), headings order, images: decorative or alt text, contrast rows flagged ⚠️ in §Copy.
- `### Responsive`: behaviour outside the designed frame width, from auto layout sizing (fill/hug/fixed) in §Layout.
- `### Analytics`: one event per user decision (`screen_viewed`, `<action>_clicked`), properties, no personal data.
- `### Open questions`: numbered, each with a recommended answer; prefer "add a state/frame in FigCraft" over prose decisions.

## Rules
- Cite layers as `#id` in backticks, only ids present in the spec. No new copy, colours or sizes: those come from the design.
- Under 60 lines per spec. No preamble, no summary of the tables.
- Something wrong in the facts (a missing state, a bad contrast): say so in Open questions; the fix is a design edit, then regeneration.
