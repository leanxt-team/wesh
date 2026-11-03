# WeshCraft spec format (v1)

An **advanced spec**: a folder in a git repository that holds a visual prototype and the front-end and back-end specifications generated from it, with machine-checkable links between all three. Plain markdown and JSON, readable without any tool; `weshcraft check` verifies it, `/wesh-plan-view-mode` iterates on it, `weshcraft_sync` keeps it in a branch.

Identify it by `specs/manifest.json` with `"schema": "weshcraft/manifest@2"` (v1 manifests: `@1`, no links).

## Layout

```
design/<name>.figcraft            source of truth: the FigCraft prototype (the only file people edit by design)
prototype/index.html              clickable prototype rendered from the design; every element has data-node="<id>"
prototype/tokens.css              design tokens as CSS custom properties
prototype/screens/*.png           FigCraft renders, when generated from a live FigCraft (visual reference)
specs/manifest.json               the extracted inventory (below); generated
specs/README.md                   index + traceability
specs/PARITY.md, parity.json      last parity result
specs/CHANGES.md                  design changelog, newest first
specs/LINKS.md                    front ⇄ back map
specs/front/screens/<key>.md      one per screen
specs/front/components/<key>.md   one per component (set)
specs/front/tokens.md, tokens.css, flows.md
specs/back/domain.md, api.md, openapi.json, conventions.md
.github/workflows/weshcraft-parity.yml | ci/weshcraft.gitlab-ci.yml   CI parity gate
```

## Identity: node ids and keys

- Every fact cites the prototype layer it comes from as `` `#<id>` `` (FigCraft node id). The same id is `data-node` in the prototype, so a reader can jump from a spec line to the pixel.
- Screens: `scr-<slug>`; components: `cmp-<slug>`; operations: `op-…`; entity fields: `Entity.field`.
- Fingerprints (12 hex) hash every visible property of a screen or component subtree; the manifest `source.hash` hashes the whole inventory.

## Spec files

Each generated markdown file has three parts:

1. **Generated sections** (tables, layout tree, acceptance criteria…): facts from the design only. Regenerated; never edit by hand.
2. **Notes** between `<!-- weshcraft:notes:start -->` and `<!-- weshcraft:notes:end -->`: the only free-form part (states, edge cases, a11y, analytics, security, open questions). Kept across regenerations; written by humans or agents (`weshcraft_write_notes`, wesh-spec-front/back).
3. **Contract**: an HTML comment `<!-- weshcraft:contract {json} -->` listing exactly which facts the file covers, e.g. for a screen:

```json
{"kind":"front-screen","key":"scr-sign-up","node":2,"fingerprint":"c2f2ec602cd9","sourceHash":"5a5d8a8b3efe1d09",
 "size":[393,600],"copy":[{"node":4,"text":"Create your account"}],"actions":[{"node":10,"type":"navigate","dest":"scr-profile"}],
 "instances":[],"inputs":[6,8],"operations":["op-create-account-10"],"components":[],
 "links":[{"rel":"triggers","node":10,"op":"op-create-account-10"},{"rel":"submits","node":6,"op":"op-create-account-10"}]}
```

Kinds: `front-screen`, `front-component`, `front-tokens`, `front-flows`, `back-domain`, `back-api`, `back-conventions`, `links`.

## Front ⇄ back links

`manifest.links.edges[]`: `{rel, node, screen, label, op | field, via?}` with `rel` one of `triggers` (▶ layer calls operation), `submits` (⇢ input is a request field), `lists` (☰ repeated layer filled by a list operation), `displays` (◉ layer shows `Entity.field`; `via` = the operation on that screen that loads it). `manifest.links.gaps[]`: `unloaded-data` (shown, nothing loads it), `unused-operation` (nothing reaches it).

Explicit sources in the design (preferred over inference): text `{{entity.field[:type]}}`, layer name `@entity.field[:type]`, layer data `pluginData.weshcraft = {"entity","field","type"}` or `{"action":"POST /x","returns":"X"}`, Dev Mode annotation `METHOD /path [→ Entity]` on a trigger layer, or on a screen frame for data the screen loads. Everything else is marked `inferred` and listed under Open questions.

## Parity (`weshcraft check`)

Fails (exit 1) when any of these differ between a fresh extraction of `design/*.figcraft` and the files: screen and component fingerprints, copy (verbatim on its own Copy row), interactions and destinations, instances, inputs, frame sizes, tokens and values, navigation edges, entities and fields, operations (spec and OpenAPI), front ⇄ back links, the prototype's source hash; plus any `#id` cited that does not exist. Gaps and source-hash drift are warnings.

## Lifecycle in git

1. **Iterate**: change the design (FigCraft, or agents through `figcraft_*` MCP tools) → specs regenerate in parallel → parity.
2. **Update**: on an existing spec folder, `weshcraft diff --against <ref>` (or `specs/CHANGES.md`) says what changed in the design; only changed specs are rewritten; Notes survive.
3. **Sync**: `weshcraft_sync` / `--sync`: `git` (commit only these paths, current branch, hooks run, optional push) or `github:` / `gitlab:` (commit to a branch through the API; PR/MR opened once, then updated with the latest changelog). Only in-sync states are synced.
4. **Gate**: the CI job re-runs `weshcraft check` on every push touching `design/`, `specs/` or `prototype/`.
5. **Build**: code is reviewed against `specs/front/screens/*.md` §Acceptance criteria, `specs/back/api.md` and `openapi.json` (`wesh-review --spec specs/README.md`).

Commit messages: `docs(specs): <name>: <change summary>`, body = prototype hash, parity, changelog lines.
