# WeshCraft spec format (v1)

An **advanced spec**: a folder in a git repository that holds a visual prototype and the front-end and back-end specifications generated from it, with machine-checkable links between all three. Plain markdown and JSON, readable without any tool; `weshcraft check` verifies it, `/wesh-plan-view-mode` iterates on it, `weshcraft_sync` keeps it in a branch.

Identify it by `specs/manifest.json` with `"schema": "weshcraft/manifest@2"` (v1 manifests: `@1`, no links).

## Layout

```
design/<name>.figcraft            source of truth for screens: a FigCraft document (edited in WeshCraft or FigCraft)
design/weshcraft.surface.json     source of truth for non-visual fronts (optional): names an OpenAPI
design/openapi.yaml|json          document and an MCP tool list, and pins tool ⇄ endpoint links
design/<server>.mcp.json          an MCP server's tools/resources/prompts (snapshot of a live server)
prototype/index.html              clickable prototype rendered from the design (data-node="<id>"), plus a
                                  catalog of MCP tools (data-node="tool:<name>") and endpoints (data-node="ep:<METHOD path>")
prototype/tokens.css              design tokens as CSS custom properties
prototype/screens/*.png           FigCraft renders, when generated from a live FigCraft (visual reference)
specs/manifest.json               the extracted inventory (below); generated
specs/README.md                   index + traceability
specs/PARITY.md, parity.json      last parity result
specs/CHANGES.md                  design changelog, newest first
specs/FUNCTIONS.md                how the product works: functions → screens, operations, data, journey
specs/LINKS.md                    front ⇄ back map
specs/front/screens/<key>.md      one per screen
specs/front/components/<key>.md   one per component (set)
specs/front/tokens.md, tokens.css, flows.md   (only with screens)
specs/front/mcp/README.md, tool-<name>.md     (only with an MCP server)
specs/front/api/README.md, ep-<method>-<path>.md   (only with a public API)
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

Kinds: `front-screen`, `front-component`, `front-tokens`, `front-flows`, `front-mcp`, `front-mcp-tool` (`name`, `fingerprint`, `input`, `op`), `front-api`, `front-endpoint` (`key`, `fingerprint`, `op`), `back-domain`, `back-api`, `back-conventions`, `links`.

## Non-visual fronts

A product's front can be an MCP server, a public API, or both, with or without screens. `manifest.surface` holds `{name, mcp: {server, tools[], resources[], prompts[]}, api: {title, servers, auth, endpoints[], schemas{}}}`. Each tool has `hints` (read-only, destructive, idempotent, open world, from MCP annotations), flattened `input` fields and a `fingerprint` over description, schemas and annotations; each endpoint has `params`, `body`, `responses`, `security` and a `fingerprint`. API schemas returned by endpoints become entities; each endpoint is an operation; links: `exposes` (endpoint → operation), `invokes` (tool → operation, from `weshcraft.surface.json` links or matching `operationId`).

## Front ⇄ back links

`manifest.links.edges[]`: `{rel, node, screen, label, op | field, via?}` with `rel` one of `triggers` (▶ layer calls operation), `submits` (⇢ input is a request field), `lists` (☰ repeated layer filled by a list operation), `displays` (◉ layer shows `Entity.field`; `via` = the operation on that screen that loads it). `manifest.links.gaps[]`: `unloaded-data` (shown, nothing loads it), `unused-operation` (nothing reaches it).

Explicit sources in the design (preferred over inference; WeshCraft's editor and `design_bind` / `design_api` write the layer-name and annotation forms): text `{{entity.field[:type]}}`, layer name `@entity.field[:type]`, layer data `pluginData.weshcraft = {"entity","field","type"}` or `{"action":"POST /x","returns":"X"}`, Dev Mode annotation `METHOD /path [→ Entity]` on a trigger layer, or on a screen frame for data the screen loads. Everything else is marked `inferred` and listed under Open questions.

## Parity (`weshcraft check`)

Fails (exit 1) when any of these differ between a fresh extraction of the design inputs and the files: MCP tool and endpoint fingerprints, tool arguments and links, the lists of tools, resources, prompts and endpoints; screen and component fingerprints, copy (verbatim on its own Copy row), interactions and destinations, instances, inputs, frame sizes, tokens and values, navigation edges, entities and fields, operations (spec and OpenAPI), front ⇄ back links, the prototype's source hash; plus any `#id` cited that does not exist. Gaps and source-hash drift are warnings.

## Lifecycle in git

1. **Iterate**: change the design (WeshCraft's Design tab, agents through the `design_*` MCP tools, or FigCraft itself) → specs regenerate in parallel → parity.
2. **Update**: on an existing spec folder, `weshcraft diff --against <ref>` (or `specs/CHANGES.md`) says what changed in the design; only changed specs are rewritten; Notes survive.
3. **Sync**: `weshcraft_sync` / `--sync`: `git` (commit only these paths, current branch, hooks run, optional push) or `github:` / `gitlab:` (commit to a branch through the API; PR/MR opened once, then updated with the latest changelog). Only in-sync states are synced.
4. **Gate**: the CI job re-runs `weshcraft check` on every push touching `design/`, `specs/` or `prototype/`.
5. **Build**: code is reviewed against `specs/front/screens/*.md` §Acceptance criteria, `specs/back/api.md` and `openapi.json` (`wesh-review --spec specs/README.md`).

Commit messages: `docs(specs): <name>: <change summary>`, body = prototype hash, parity, changelog lines.

## Product functions

`specs/FUNCTIONS.md` (contract kind `functions`) describes the product as a handful of functions. Each has a key (`fn-<slug>`), a name, a one-line purpose, who uses it (`user`: people in the app, `agent`: AI agents through MCP tools, `api`: integrations through the public API), its screens (in journey order), operations, MCP tools and public endpoints, the entities it reads and writes, and the functions it leads to (navigation from one of its screens to another function's). A Mermaid diagram shows who → functions → data, with ⇒ for where each function leads.

Functions are declared in the design: the first page's `pluginData.weshcraft` holds `{"functions": [{"name", "summary", "screens": [node ids], "operations": ["METHOD /path"], "tools": ["name"]}]}` (`operations` and `tools` only for those no screen reaches). A service without screens declares them in `weshcraft.surface.json` (`"functions"`, same shape, no screens). Until declared, they are suggested from the prototype: flows, canvas sections, wizard steps (one way in, one way on), screens about the same entity, variants of one screen, API tags; the spec says so.

The other specs follow them: a screen spec's header names its function (contract field `function`), `back/api.md` gives each operation's function, and `front/flows.md` and `LINKS.md` group screens by function. Parity: `functions-differ` (error) when FUNCTIONS.md no longer matches; warnings `functions-suggested`, `not-in-a-function` (a screen, operation or tool in none), `function-unknown-ref` (a declared screen or operation that is gone) and `empty-function`; `function-differs` (error) when a screen spec names another function.
