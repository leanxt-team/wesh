---
name: wesh-plan-view-mode
description: Plan in view mode. Iterate on a FigCraft prototype through WeshCraft MCP, generate front and back specs in parallel that match it exactly, review live in the browser, publish prototype + specs to GitHub or GitLab. Use for /wesh-plan-view-mode.
disable-model-invocation: true
argument-hint: "[design.figcraft | --attach <port>] [--repo owner/name] [--gitlab]"
---

`/wesh-plan`, but decisions land in the prototype, not in prose. Prototype is the source of truth; specs are generated from it and contract-checked against it. Building the wrong screen is the most expensive token spend.

## 0. Setup (once)
- `weshcraft_status` tool missing: tell user to run `npx weshcraft init` (writes `.mcp.json`: WeshCraft MCP + live FigCraft) or `claude mcp add weshcraft -- npx weshcraft mcp --mcp --web`, restart, rerun. Stop.
- `sourceKind: mcp`: `figcraft_*` tools design live. `file`: read-only here; user edits in FigCraft, WeshCraft regenerates on save.
- Give user the live view URL from `weshcraft_status` (`web`). Browser shows clickable prototype, spec builder filling in parallel, parity. They watch; you work.

## 1. Facts first, yourself
As `/wesh-plan`: repo entry points, existing API, models, components, `GLOSSARY.md`, ADRs (`codegraph_explore` or `wesh-scout`). Then `weshcraft_manifest`: screens, copy, interactions, components, tokens, inferred entities and operations. Never ask user what manifest or repo answers.

## 2. Frontier rounds, answered in the design
Same rounds as `/wesh-plan` (numbered, recommended answer, "yes" accepts). Route each settled answer:
- Changes what user sees or does (screen, copy, state, flow, field, button) → edit FigCraft: `figcraft_batch` (one undo step), `figcraft_create_node`, `figcraft_set_properties`, `figcraft_run_command` (`proto.interaction.add`, `component.*`, `variable.*`). Reuse existing components and variables. Then `figcraft_screenshot` of the screen so user confirms.
- Data a layer shows → bind it: text `{{trail.name}}` / `{{trail.distance:number}}`, or layer name `@trail.rating:number`. Becomes an explicit entity field.
- Back-end call → Dev Mode annotation on the trigger layer: `POST /trails` (`figcraft_run_command annotation.add`). Becomes an explicit operation.
- Not visual (rule, limit, perf, security, analytics) → `weshcraft_write_notes` on the owning spec.
Edits through `figcraft_*` regenerate specs automatically (debounced). Never write a fact into notes that the design contradicts: change the design.

## 3. Generate in parallel
`weshcraft_generate`. Then fan out: one subagent per group, max 6 at once, each told to use `wesh-spec-front` (screens, components, tokens, flows) or `wesh-spec-back` (domain, API, conventions), read its specs with `weshcraft_read_spec`, write only Notes with `weshcraft_write_notes`. Headless alternative: `weshcraft serve --agent` does the same pass with `claude -p`.

## 4. Parity gate
`weshcraft_check` must be `ok`. Stale or missing → `weshcraft_generate`. Copy/interaction drift → the design changed: regenerate, never hand-edit generated sections. Inferred entities/operations still open → ask in the next round or annotate the design.

## 5. Spec summary
Reply in `/wesh-plan` shape, under ~60 lines, pointing at files instead of restating them:
```
# <feature>
Problem / Solution: <user view, 1-3 lines each>
Prototype: prototype/index.html (<n> screens) · parity <score>% · live: <url>
Acceptance: specs/front/screens/*.md §Acceptance criteria (+ list the 3-5 that matter most)
Decisions: entities, operations, components reused (link specs/back/domain.md, api.md)
Test seams · Non-goals · Slices (vertical, each = screens + operations it needs)
```

## 6. Publish (outward, confirm first)
On user yes: `weshcraft_publish {provider: github|gitlab, repo, branch?, base?}`. Commits `prototype/`, `specs/`, the `.figcraft` source and a CI parity check; opens or updates the PR/MR. Give the URL. Later code review: `wesh-review --spec specs/README.md`.

Do not implement until user confirms the spec, unless they asked to go straight on.
