---
name: wesh-plan-view-mode
description: Plan in view mode. Design the prototype through WeshCraft MCP (a spec-oriented FigCraft), generate front and back specs in parallel that match it exactly, then update, sync or push the advanced spec in a git repo. Use for /wesh-plan-view-mode.
disable-model-invocation: true
argument-hint: "[design.figcraft | --attach <port> | openapi.yaml | weshcraft.surface.json] [new | update | sync | push] [github:owner/repo | gitlab:group/project | git]"
---

`/wesh-plan`, but decisions land in the prototype, not in prose. Output is the **WeshCraft advanced spec**: design + clickable prototype + contract-checked front/back specs + front ⇄ back links + changelog, in git. Format: `FORMAT.md` next to this file. Building the wrong screen is the most expensive token spend.

## 0. Setup and mode
- `weshcraft_status` tool missing: tell user to run `npx weshcraft init --client claude` (Claude Code: `.mcp.json`) or `npx weshcraft init --client opencode --global` (OpenCode / OpenChamber plugin; in OpenChamber add the WeshCraft folder in Settings → Extensions for the sync panel and the full interface); `--sync git` keeps this repo in step, restart, rerun. Stop.
- `design_*` tools present: you edit the design (the project's `.figcraft`) directly; user edits the same document in the browser's Design tab at the same time (shared undo). `design_new` only: no design yet, start one if the feature has screens. `sourceKind: mcp`: a live FigCraft, use `figcraft_*` instead. Neither, with a surface: the product's front is an MCP server and/or a public API (no screens); `init --surface openapi.yaml` or `--mcp-server "cmd"` sets that up.
- Give user the live view URL from `weshcraft_status` (`web`): design editor, prototype, spec builder filling in parallel, Front ⇄ back map, parity. They watch and can adjust by hand; you work.
- Mode from the argument, else from the repo:
  - `new` (no `specs/manifest.json`): steps 1-7.
  - `update` (an advanced spec exists: `specs/manifest.json`, schema `weshcraft/manifest@*`): step U, then 2-7 for what changed.
  - `sync` / `push`: step 7 only, with the given target. `push` pushes; confirm first.

## U. Update an existing spec
1. Branch state: `git status`, `git fetch`. Behind its upstream → fast-forward only (`git merge --ff-only @{u}`); diverged or dirty spec paths → stop, tell user. Never rebase, reset or force.
2. `weshcraft_generate`, then `weshcraft diff --against HEAD` (or read `specs/CHANGES.md` top entry): what the design changed since the committed spec. Summarise in ≤8 lines: screens, copy, interactions, components, operations, data, links.
3. Only specs whose contract changed are rewritten; Notes survive. Re-check Notes of changed specs against the change (stale edge cases, removed fields) with `wesh-spec-front` / `wesh-spec-back`; fix only those.
4. Continue at step 2 for open questions the change raises; else step 5.

## 1. Facts first, yourself
As `/wesh-plan`: repo entry points, existing API, models, components, `GLOSSARY.md`, ADRs (`codegraph_explore` or `wesh-scout`). Then `design_tree` (ids, layout, links, API annotations; one line per layer) and `weshcraft_manifest` for entities and operations. Never ask user what tree, manifest or repo answers.

## 1b. How the product works
`design_functions`: the product's functions (suggested from the prototype until declared). Settle them in the first round: a handful (not one per screen), each a verb phrase the user would say ("Find a trail", "Pay"), a one-line purpose, its screens; API-only operations and MCP tools that no screen reaches go to the function they serve. Declare with `design_functions {functions:[…]}` (or `set` for one). Every later round says which function it changes; a new screen goes into a function in the same batch. `specs/FUNCTIONS.md` is the first thing a reader opens: keep it true.

## 2. Frontier rounds, answered in the design
Same rounds as `/wesh-plan` (numbered, recommended answer, "yes" accepts). Route each settled answer:
- Changes what user sees or does (screen, copy, state, flow, field, button) → one `design_edit` per settled round: all its ops in one batch (one undo step for user), `ref` to wire new layers (`{op:"screen",ref:"s"}`, `{op:"create",parent:"s",…}`, `{op:"link",id:…,to:"s"}`). Reuse components (`instance`) and tokens (`useToken`); auto layout (`layout`, `sizing`) over x/y. `design_text` for copy-only rounds. `design_screenshot` (if available) or the live URL so user confirms. Live FigCraft instead: `figcraft_batch`, `figcraft_set_properties`, `figcraft_run_command`.
- Data a layer shows → `{op:"bind", id, entity:"trail", field:"rating", type:"number"}`. Becomes an explicit entity field.
- Back-end call → `{op:"api", id: <button>, method:"POST", path:"/trails", returns:"Trail"}`; data a screen loads → same op on the screen frame (`GET /users/me → User`). Explicit operation, linked to the layers that trigger it, submit to it, show what it returns.
- Pass `wait:true` on the last edit of a round: parity, design changes and gaps come back in the reply.
- Not visual (rule, limit, perf, security, analytics) → `weshcraft_write_notes` on the owning spec.
Every design edit (yours, user's in the browser, FigCraft saving the file) regenerates the specs automatically. Never write a fact into notes that the design contradicts: change the design. User edited by hand meanwhile: `design_tree` again before batching on stale ids.

No screens (MCP server / API): the source of truth is `design/openapi.yaml`, the MCP tool list (or the server's code) and `weshcraft.surface.json`. Answers land there instead: a tool's name, description, input schema and annotations (`readOnlyHint`, `destructiveHint`…), an endpoint's parameters, body and responses, and `links` from tools to endpoints. Agents are the users of MCP tools: settle descriptions and safety hints as carefully as copy on a screen.

## 3. Generate in parallel
`weshcraft_generate`. Fan out: one subagent per group, max 6 at once, each told to use `wesh-spec-front` (screens, components, tokens, flows) or `wesh-spec-back` (domain, API, conventions), read with `weshcraft_read_spec`, write only Notes with `weshcraft_write_notes`. Update mode: changed specs only. Headless alternative: `weshcraft serve --agent`.

## 4. Front ⇄ back links
`weshcraft_links` (or `specs/LINKS.md`): layer → operation (▶ triggers, ⇢ submits, ☰ list filled by), layer → entity field (◉ shows, + operation that loads it). Each gap is a question for the next round:
- field shown, nothing loads it → annotate the loading operation on that screen, or drop the binding.
- operation nothing reaches → wire it to a layer or cut it.
- inferred operation or field → confirm by binding/annotating in the design.

## 4b. Code ⇄ spec (codegraph)
Existing code first: `codegraph_explore "how does <function> work"` (the product graph `design/weshcraft.graph.mjs` links functions → screens, components → operations → entities → the code tagged for them), `weshcraft_trace {untraced:true}` for what has no code yet.
Writing or changing code from the specs (now, or in a later `/wesh-tdd`, `/wesh-refactor`): put the element's tag in a comment on the symbol that implements it, the `Code tag` from the spec header: `// @weshcraft scr-sign-up` on the screen component, `// @weshcraft POST /users` on the client call and on the route handler, `# @weshcraft User` on the model; several refs: `@weshcraft fn-join, User`. One tag per implementing symbol, in every language of the repo. Then `weshcraft_trace`: it rewrites the product graph and `specs/TRACE.md`; `codegraph sync` and the graph links each element to its code. Before changing shared code: `codegraph impact <symbol> --depth 4` names the screens and functions it touches. A `trace-unknown` warning (a tag naming nothing) after a design change: move the tag to the new key.

## 5. Parity gate
`weshcraft_check` must be `ok`, with no `functions-suggested` or `not-in-a-function` warning left. Stale or missing → `weshcraft_generate`. Drift → design changed: regenerate, never hand-edit generated sections.

## 6. Spec summary
Reply in `/wesh-plan` shape, under ~60 lines, pointing at files instead of restating them:
```
# <feature>
Problem / Solution: <user view, 1-3 lines each>
Prototype: prototype/index.html (<n> screens) · parity <score>% · live: <url>
Changed: <weshcraft diff summary, update mode only>
Acceptance: specs/front/screens/*.md §Acceptance criteria (+ the 3-5 that matter most)
Decisions: entities, operations, components reused (specs/back/domain.md, api.md)
Functions: specs/FUNCTIONS.md — <name: purpose> per function, nothing outside a function
Code: specs/TRACE.md — <traced>/<total> elements have code; untraced: <list or none>
Links: specs/LINKS.md — <n> operation links, <n> data links, gaps: <none | list>
Test seams · Non-goals · Slices (vertical, each = screens + operations it needs)
```

## 7. Sync / push (outward, confirm first)
Only an in-sync state is synced. On user yes:
- keep in sync: `weshcraft_sync {target: "git" | "github:owner/repo" | "gitlab:group/project", auto: true}`. `git` commits only the spec paths on the current branch, hooks run; `push: true` only when user asked (mode `push`). Remote targets commit to a branch through the API and open/update one PR/MR whose description carries the latest changelog; access is inherited (OpenChamber account, gh/glab login, git credentials), never ask user for a token unless sync reports none.
- one-off PR/MR: `weshcraft_publish {provider, repo, branch?, base?}`.
Commit messages come from the changelog (`docs(specs): <name>: <summary>`); do not rewrite them. Give the commit or URL. Later code review: `wesh-review --spec specs/README.md`.

Do not implement until user confirms the spec, unless they asked to go straight on.
