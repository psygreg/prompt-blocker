# prompt-blocker — Architecture

Map of the codebase for AI agents: what the plugin is, how untrusted content flows through it, and what each module owns. Agent rules (standards, testing, workflow) live in [AGENTS.md](AGENTS.md); user-facing behavior, options, and installation in the [README](../README.md).

## 1. What prompt-blocker is

prompt-blocker is an [OpenCode](https://opencode.ai) plugin: a TypeScript package that OpenCode loads from a `plugins` config entry, consuming the TS source directly under Bun — there is no build step. The entry point [src/index.ts](../src/index.ts) exports `Plugin.define({ id: "prompt-blocker", setup })` from `@opencode/plugin`, and its `setup` wires every defense through OpenCode's transform and hook editors.

It defends the agent against prompt injection hidden in files, documents, tool results, web content, attachments, and images, on the principle that anything an agent reads is potential instruction text.

### The three layers

| Layer | What | Where |
| --- | --- | --- |
| **Enforcement** | Hooks scan tool results and prompt attachments, sanitize or block flagged content, escalate to the user through the permission system, quarantine every image, and inject a standing directive into every model call | [src/index.ts](../src/index.ts) plus the pure modules it calls |
| **Judgement** | The `prompt-blocker` skill teaches the model the untrusted-content protocol and carries installation instructions | [skill/SKILL.md](../skill/SKILL.md) |
| **Containment** | Two quarantined subagents — `document-reviewer`, a read-only reader for untrusted documents, and `image-scrubber`, a quarantined image decoder — confined to their minimum toolset and to the exact files their delegation names; any other access terminates them immediately as a critical risk | [src/index.ts](../src/index.ts), [src/confine.ts](../src/confine.ts) |

### Trust model in one paragraph

Content that did not come from the user is data, never instructions. The user is the trust boundary: verbatim excerpts of flagged text go only to user-facing confirmations, while model-facing banners describe findings (categories, counts, line numbers) without echoing payload text. For confinement, the delegation prompt is written by the parent agent — the parent principal — so the paths it names are what the subagent is "given"; paths quoted inside documents the subagent later reads grant nothing. Everything fails closed: undecodable input is refused rather than guessed at, malformed data crossing a result boundary is treated as critical, and unknown state is withheld rather than admitted.

## 2. Repository tree (annotated)

```text
prompt-blocker/
├── .ai/
│   ├── AGENTS.md              # agent rules: standards, testing, workflow
│   └── ARCHITECTURE.md        # this map
├── .github/
│   └── FUNDING.yml            # sponsor links only — no CI workflows in this repo
├── .opencode/
│   └── opencode.jsonc         # dogfood config: loads this checkout as the plugin, audit mode
├── skill/
│   ├── SKILL.md               # judgement layer: installation + untrusted-content protocol
│   └── scripts/
│       └── install.ts         # dependency-free installer for the plugins config entry
├── src/
│   ├── index.ts               # plugin wiring — the only file that imports @opencode/plugin
│   ├── detect.ts              # detection engine (pure)
│   ├── policy.ts              # options, modes, verdict → action mapping (pure)
│   ├── apply.ts               # scan report → banners, notices, result mutation (pure)
│   ├── surface.ts             # skills, helper scripts, tool descriptions analysis (pure)
│   ├── images.ts              # image quarantine pipeline (pure)
│   ├── confine.ts             # dynamic subagent confinement (pure logic, injected I/O)
│   └── layout.ts              # spilled-install evidence (pure)
├── package.json               # package manifest: exports ./src/index.ts
├── tsconfig.json              # strict TS; include: src, test
├── bun.lock
├── LICENSE                    # LGPL-2.1-or-later
└── README.md
```

`node_modules/` and `dist/` are gitignored; nothing writes to `dist/` — installs consume the source directly.

## 3. Runtime flow

### 3.1 Registration (`setup`)

`setup(ctx)` parses `Options` via `parseOptions`, detects the install shape (bundled skill present? loose files spilled into a plugins directory?), builds the quarantine state, and registers everything, each guarded by its option flag, in this order:

1. skill transform — register the `prompt-blocker` skill (`skill: true`)
2. agent transform — register the `document-reviewer` subagent (`agent: true`)
3. agent transform + tool transform — register the `image-scrubber` subagent and its `image_scrub` tool (`images: true`)
4. confinement hooks (`agent || images`): session `prompt` (path grants), session `generate` (fail terminated sessions), tool `execute.after` (parent-side reporting and static-denial burn), tool `execute.before` (minimum toolset + file grant), permission `evaluate` (clamp allow/ask outcomes to deny)
5. tool `execute.before` — the image read guard (`images`)
6. skill transform + tool transform — the surface scans: skill bodies + bundled helper scripts, then tool descriptions + parameter schemas (`surface`)
7. session `context`/`generate`/`compaction` hooks — the standing untrusted-content directive (`directive`)
8. tool `execute.after` — the main result-scan hook (always on)
9. session `prompt` — attachment scanning (always on)
10. command transform — the `/prompt-blocker` command

`setup` returns a `dispose()` that flips the disposed flag (stopping the findings log) and disposes every registration.

### 3.2 Per-prompt flow

Every prompt passes through two `session prompt` hooks:

1. **Confinement grant.** Every file path the prompt names (absolute, `~/`-expanded, `file://` URIs, quoted paths, relative dotted tokens) is recorded as granted to that session — the delegation grant quarantined subagents are later checked against. Granting never fails the prompt it rides on.
2. **Attachment scan.** Attachments are classified first: `data:image` URIs, and files whose magic bytes sniff as an image (not just by extension — a text file named `*.png` takes the text path), are quarantined; non-local `data:`/http images get a staged copy under `staging/` for the scrubber handoff. Everything else readable is text-scanned up to `maxScanBytes` (binary or mostly-non-UTF8 files are kept unscanned); `trustedPaths` skips it all. `actionFor` decides per attachment: keep, keep with an advisory note, ask the user via the permission system (allow keeps a warning, deny removes), or remove. Removed and quarantined attachments are dropped from `prompt.files`, their mention spans replaced with same-length `…` runs so offsets stay stable, and notices are appended to the prompt text.

### 3.3 Per-tool-result flow

The main tool `execute.after` hook runs for every completed result:

1. `read` results targeting a `trustedPath` skip everything.
2. `image_scrub` results get their metadata scan escalated (see 3.4).
3. Image parts in the result are replaced by quarantine notices — unless the copy is already cleared (then only its earned banner applies) or the caller is the scrubber viewing its own output.
4. Results carrying a native rich document (PDF/office/RTF by MIME) get an advisory banner: their content is not text-scannable.
5. All text (`content` string/parts plus `output`) is joined and scanned. `actionFor` maps the verdict to an action; `confirm` escalates through `permission.assert` with a content-pinned resource ("allow always" is saved against source + content hash); `applyToResult` annotates, sanitizes, or replaces the content. Blocked results stand alone; banners ride only content that is actually delivered.
6. `subagent` results whose text is admitted may clear the sanitized image copies they name — the only path to `cleared`.
7. Everything is logged as a finding (kind `tool`).

### 3.4 Image quarantine flow

No raw image ever enters model context:

1. **Boundary.** Image attachments are withheld before admission and image parts inside tool results are replaced by notices naming a handoff path: the original local path when it exists, otherwise a staged copy of `data:`/http bytes.
2. **Decode.** The model delegates to `image-scrubber`, whose only tool `image_scrub` stats the file (64 MiB cap), sniffs the magic bytes, extracts container metadata and scans it (`metaScan`), then runs the deterministic `scrubImage` pipeline and writes the sanitized copy to `clean/`, registering it as the only readable image.
3. **Escalation.** The tool's own result handling validates the metadata scan shape (anything malformed is treated as critical, score 999) and applies the mode: clean → admitted; flagged → banner recorded; confirm → user decision; blocked or declined → the sanitized copy is deleted and the image stays locked forever.
4. **Admission.** The parent's `subagent` report (what the image shows plus all visible text) passes the same text guards; an admitted report clears the sanitized copies it names for direct access. The image read guard denies everything else — unsanitized originals always, sanitized copies until their report is admitted. `trustedPaths` is the only bypass. Sanitized copies live under `$TMPDIR/prompt-blocker-quarantine/<project-hash>/{clean,staging}` and stale files are swept after 24 h.

### 3.5 Confinement flow

- **Grants.** Every prompt of every session seeds the grant set; grants are insertion-ordered and capped (64 paths per session, 200 sessions) and realpath-expanded, so a symlink alias of a granted file passes and nothing else does.
- **Checks.** A quarantined agent may only call its minimum toolset (`document-reviewer`: `read`; `image-scrubber`: `read` + `image_scrub`) and only touch granted paths; the scrubber may additionally always read under `clean/`. A session with no recorded grants (the shape left behind by a plugin reload mid-run) degrades to permission-level confinement instead of terminating legitimate work; any prompt re-seeds the grant.
- **Violations.** Recorded once per session (reason: `tool`, `path`, or `burned`), logged as a critical `confinement` finding, the offending tool call rejected with `terminationError`, a delayed interrupt scheduled as a backstop, the next model call failed via the `generate` hook, and the parent's `subagent` result replaced (or its error joined) with the critical `confinementReport`. Static permission denials, which never reach the `evaluate` hook, burn the session through `observeDeniedCall` when the error message starts with `Permission denied:`.

### 3.6 The `/prompt-blocker` command

Reports the mode and options, any degraded-install notice and spilled files, flagged surface artifacts, `trustedPaths`, confinement state with each agent's minimum toolset, the quarantine directory with cleared-copy counts, options being ignored (`skipTools`, `trustedSurface`), and the ten most recent findings. Delivered as a session prompt.

## 4. Module map — `src/`

### 4.1 `src/index.ts` — plugin wiring

The only OpenCode-coupled file; everything below it is pure. Owns:

- **Constants.** `PERMISSION_ACTION` (`prompt-blocker.content` — the action confirmation prompts ride; pre-decide with permission rules like `{ "action": "prompt-blocker.content", "effect": "deny" }`), the id constants (`SKILL_ID`, `AGENT_ID`, `SCRUBBER_AGENT_ID`, `SCRUB_TOOL`), the image caps (`IMAGE_INPUT_CAP` 64 MiB, `IMAGE_STAGE_TIMEOUT_MS` 15 s, `IMAGE_SWEEP_AFTER_MS` 24 h), `RICH_MIME_RE` (native documents), and the message texts: `DIRECTIVE` + `COMPACTION_DIRECTIVE` (the standing directive), `AGENT_SYSTEM` + `AGENT_PERMISSIONS` (deny-all → allow `read` → ask on `.env*` → allow `external_directory`; 12-step budget), `SCRUBBER_SYSTEM` + `scrubberPermissions` (deny-all → allow `image_scrub` → allow `read` under `clean/`; 8-step budget), and the skill/tool/agent descriptions.
- **Quarantine state.** `quarantinePaths` (sha256 of the project key → `$TMPDIR/prompt-blocker-quarantine/<hash>/{clean,staging}`, with a stale-file sweep), `imageRecords` (cleanPath → source label, scrub-admitted, cleared, earned banner), `stagingLabels`, and `logFinding` — a serialized read-modify-write of the findings list into `ctx.storage` under `"findings"`, capped at `logLimit`, which must never break enforcement.
- **Install-shape checks.** `loadSkill` reads `../skill/SKILL.md` relative to the module; a missing file marks a degraded install; `spillEvidence` over candidate plugin directories names leftover loose files in the degraded notice and `/prompt-blocker` status.
- **The `image_scrub` tool** (`executeScrub`): validate → sniff → extract + scan metadata → `scrubImage` → write and register the sanitized copy → report (fail-closed on every step).
- **The main result-scan hook**, the attachment/prompt hook, the confinement wiring (see section 3), and the `/prompt-blocker` command, registered in the order of section 3.1.
- **Helpers.** `readCapped`/`readHead` (bounded reads, binary detection), `schemaText` (cyclic-safe JSON of tool input schemas), `readSkillScripts` (helper scripts bundled next to a SKILL.md, depth ≤ 2, ≤ 50 files), `isScanReportShape` (report validation across the result boundary), `targetPath`, `escapeRegExp`.

### 4.2 `src/detect.ts` — detection engine (pure)

- **Types.** `Verdict` (`clean` | `suspicious` | `likely` | `critical`), `CategoryId` (18 categories), `Detection` (id, label, count, weight, lines, details, concealment, excerpts), `ScanReport` (verdict, score, detections, `concealedPhrase`, `decodedPayload`, scannedBytes, truncated), `ScanOptions`.
- **Entry points.** `scanText(text, options)` → `ScanReport`; `sanitizeText(text, report, options)` → `{ text, notes }`; `normalizeForPhraseScan` (single-pass entity/percent decode to catch obfuscated phrases); `PHRASE_FAMILY_CAP = 44`.
- **Signals.** Zero-width and invisible format characters, bidirectional overrides (Trojan Source), soft hyphens in numbers, private-use code points (symbol fonts), dense variation selectors, and Unicode tag runs decoded to their ASCII payload (`decodeTagRuns`).
- **Phrase classes** (`PHRASE_CLASSES`, id / weight / container-only): override 22, identity 14, secrecy 22, exfiltration 28, reveal 16, targeting 8, tool-invocation 22 (container-only); plus the user-supplied `extraPhrases` class (weight 20). Visible phrase findings share `PHRASE_FAMILY_CAP`, so visible wording alone can reach `likely` but never `critical`.
- **Containers** (`extractContainers`): HTML comments, `<script>`/`<style>` bodies, `alt`/`title`/`aria-*`/`placeholder`/`data-*` attribute values, `<meta>` content, and directive-style frontmatter keys — all phrase-scanned with the container-only classes included.
- **Hidden styling** (`HIDDEN_STYLING` + `markupSpans`): tiny fonts, `opacity: 0`, `display:none`, `visibility:hidden`, off-screen positioning, transparent and white-on-white text, `hidden` attributes — counted only inside a start tag (read quote-aware), a `<style>` element, or a `{}` rule block, so prose that merely names `display:none` hides nothing.
- **Encoded payloads** (`scanEncodedPayloads`): base64 and hex runs ≥ 80 chars, decoded and phrase-scanned.
- **Verdict.** `critical` when a payload decoded, the score reaches 80, or concealment combines with a concealed phrase or a dangerous visible phrase (override/exfiltration/secrecy); `likely` ≥ 40; `suspicious` ≥ 8. Individual category weights are capped (e.g. tag-characters 50 per occurrence, cap 100).
- **Sanitization.** Invisible/format/PUA/variation code points → U+FFFD, soft hyphens dropped, entity-encoded invisibles neutralized, phrase-bearing HTML comments and decoded payloads replaced with marker text. Hidden CSS is flagged but left in place — rewriting markup risks corrupting the document.

### 4.3 `src/policy.ts` — options, modes, verdict → action (pure)

- **`Options`** (mode, maxScanBytes, trustedPaths, extraPhrases, agent, directive, skill, logLimit, permissiveConfirmAt — fixed at `critical` —, surface, images) and `parseOptions` with clamped integers: `maxScanBytes` 1024–16 MiB, default 256 KiB; `logLimit` 0–1000, default 50.
- **`REMOVED_OPTIONS`** (`skipTools`, `trustedSurface`): name-based exemptions were removed because anyone can choose a name; `removedOptionsIn` reports them so `/prompt-blocker` can say they are ignored.
- **`actionFor(report, options)`**: standard — suspicious → annotate, likely → sanitize, critical → confirm; strict — likely and critical → block; permissive — critical → confirm, else annotate; audit — annotate always. `surfaceActionFor` turns confirm into block, because surface findings are enforced at load time when no session exists to ask.
- **`isTrustedPath`** (tilde expansion, prefix or wildcard match) and `matchesPattern` (mirrors OpenCode permission patterns).

### 4.4 `src/apply.ts` — application layer (pure)

- **Result shapes.** `TextPart`, `FilePart`, `ContentValue`, `ResultLike`; `extractText` (content string/parts plus `output`).
- **Targeting.** `describeTarget` (tool + input → human-readable label), `pinnedResource` (sha256-pinned permission resource, so "allow always" covers exactly that content).
- **Model-facing messages** (never echo payloads): `flagBanner`, `blockedNotice`, `richDocumentAdvisory`, `formatReport`, and the image notices `imageQuarantineNotice`, `imagePartNotice`, `imageReadDeniedNotice`, `imageScrubBlockedNotice`.
- **User-facing messages** (may quote short excerpts): `userConfirmation`, `attachmentAdvisory`, `attachmentRemovedNotice`.
- **Result mutation.** `applyToResult` (pure): block → content replaced by the notice; sanitize → `sanitizeText` plus banner; the replacement carries all text parts together, so sanitized text never sits beside unsanitized text, and file parts are kept. `annotateResult` prepends a banner without touching text.

### 4.5 `src/surface.ts` — agent-surface analysis (pure)

- **Input.** `SurfaceItem` `{ kind: "skill" | "tool" | "script", id, text }`; `analyzeSurface(items)` → per-id `ScanReport`.
- **Per-artifact checks.** `scanToolSurface` — tool-poisoning (weight 90: `HIDE_FROM_USER`, or secret steering: a `LOCAL_SECRET`/`RETRIEVED_CREDENTIAL` match with a move verb and a directive inside a 160-char window that stops at the parameter-schema boundary; local secrets accept any directive, retrieved credentials need a strong one), tool-steering and cross-tool-flow (22 × min(3 hits) each). `scanScript` — pipe-to-shell (25), decode-and-exec (60), persistence hooks (40), secrets read next to network calls (70).
- **Cross-artifact checks.** `findChains` — a staged path consumed by another artifact (60), and a secret source ↔ outbound sink split across artifacts (40, one finding per artifact); `fragmentedPairs` — instruction phrases only present when two adjacent artifacts are read back to back (60).
- **Verdict combination.** `combineReports`: the textual categories (`tool-steering`, `cross-tool-flow`, `coordinated-chain`, `fragmented-phrase`) share `PHRASE_FAMILY_CAP`, so they can raise a verdict to `likely` but never to `critical` — critical needs something hidden, decoded, or script behavior, the same bar ordinary files are held to.

### 4.6 `src/images.ts` — image quarantine (pure)

- **Recognition.** `extensionFormat` and `sniffImageFormat` (magic bytes: png, jpeg, gif, webp, bmp, tiff, heic, avif), `IMAGE_EXTENSIONS`, `looksLikeImage`.
- **Metadata inventory** (`extractMetadata` plus per-container parsers): PNG tEXt/zTXt/iTXt/eXIf/iCCP chunks, JPEG COM and APPn segments (Exif, ICC, printable-ratio fallback) via `walkJpeg`, GIF comments and extension blocks, WebP EXIF/XMP/ICCP, and a `printableRuns` sweep for containers without a structural parser. Each field is wrapped in an HTML comment, so the scanner's concealment rules apply to metadata text.
- **Canonical containers.** `canonicalizePng` keeps only IHDR/PLTE/tRNS/IDAT/IEND; `canonicalizeJpeg` keeps quantization/huffman/frame/scan segments plus entropy data and drops every APPn and COM — every non-essential chunk or segment is gone, including ICC profiles the encoder would preserve.
- **The pipeline** (`scrubImage`): pixel budget (`imagePixelBudget`, `MAX_PIXELS` 16 MP — the decompression-bomb guard) → `Bun.Image` decode with auto-orient (animated input flattens to its first frame) → ±2 % resample with a random kernel (bilinear/cubic/mitchell) → ±0.6 % brightness/saturation jitter → canonical encode (PNG for png/gif/bmp sources, via a lossy JPEG detour so LSB steganography does not survive lossless re-encoding; JPEG otherwise at `DEFAULT_JPEG_QUALITY` 82 with per-image jitter) → canonical container rewrite → decode verification with the expected shape. Any failure throws, so the image stays quarantined. `rng` is injectable for tests.

### 4.7 `src/confine.ts` — dynamic confinement (pure logic, injected I/O)

- **`AGENT_TOOLS`** (reviewer: `read`; scrubber: `read` + `image_scrub`) and `CONFINEMENT_MARKER` (`prompt-blocker CRITICAL`, so report rewrites recognize their own text).
- **Path extraction.** `extractPaths` (capped at 64 KiB; pass 1: `file://` URIs and quoted paths, masked out so the looser passes never carve fragments out of an already-granted path; then bare `~/`, `./`, `../`, drive-letter, and absolute paths; then relative dotted tokens), `resolveTarget`, `underDir`.
- **Decisions.** `checkAccess` — the pure heart: minimum toolset, grant match by absolute path or realpath (symlink-alias aware), the scrubber always allowed under `cleanDir`, and sessions with no recorded grants degrade to allowed. `toolPath` and `permissionTarget` interpret tool inputs and permission resources (read resources are paths; `external_directory` resources are directory boundaries with the trailing `/*` stripped).
- **State.** The `Confinement` class with injected deps (`realpath`, `now`, `onViolation`): `grant` per prompt, `checkToolCall`, `clampPermission`, `observeDeniedCall`, `violationOf`; caps at 64 grants/session, 200 sessions, 100 violations.
- **Notices.** `terminationError` (thrown inside the violating subagent), `generateError` (fails its next model call), `confinementReport` (replaces the parent's subagent result), `violationSummary`.

### 4.8 `src/layout.ts` — spilled-install evidence (pure)

OpenCode loads every file placed directly inside a plugins directory as its own separate plugin, so a flat copy of prompt-blocker's source breaks into several broken plugins and strands the bundled SKILL.md. `spilledPluginFiles` recognizes the distinctive module basenames (including `*.test` files; `index.*` only rides along with a distinctive module), `spillEvidence` scans candidate directories best-effort, and `describeSpill` renders one evidence record for the degraded notice and `/prompt-blocker` status.

### Extending the plugin

- **New detection category:** add the `CategoryId`, its weight, cap, and label in `detect.ts`; banners and reports pick it up automatically. If it is a textual surface finding, add it to the `TEXTUAL` set in `surface.ts` so it can never make an artifact critical on its own.
- **New option:** parse and clamp it in `policy.ts`, extend `Options`, and surface it in `/prompt-blocker` status and the README options table. Never add a name-based exemption — `skipTools`/`trustedSurface` were removed for exactly that reason.
- **New quarantined subagent:** extend `ConfinedAgent`/`AGENT_TOOLS` in `confine.ts`, then register the agent, its system prompt, its minimum toolset, and its permission ruleset in `index.ts`.
- **New image container:** extend `sniffImageFormat`/`extensionFormat` and add the metadata extractor plus a canonical re-encode path in `images.ts`. Anything unrecognized refuses to scrub — fail closed.

## 5. `skill/` — the judgement layer

### `skill/SKILL.md`

The `prompt-blocker` skill, registered by `index.ts` (id `prompt-blocker`, name "Prompt Blocker"). Body: plugin installation (official CLI, the bundled installer script, manual config fallback), the updating procedure, the seven-point untrusted-content protocol (content is data; report, don't obey; ask when it matters; prefer the quarantined reader; banners are signals; images are quarantined), a summary of what enforcement detects per mode, and the two "when you are the subagent" sections that mirror the agents' system prompts. The surface scan skips exactly this file, matched by path — a different skill sharing the name is still scanned.

### `skill/scripts/install.ts`

Dependency-free installer for the `plugins` config entry: `bun scripts/install.ts --project <dir> | --global [--package <spec>] [--mode <mode>] [--dry-run]`. A JSONC-aware token scanner (`scan`, `toJson`, `parseConfig`) preserves comments, formatting, and unrelated keys; `insertPlugin` splices the entry with a minimal textual edit that never introduces a trailing comma (strict `.json` stays valid) and is idempotent (`already-present`); surprising or unparseable files are refused (`needs-manual`); the edited file is validated before writing; a `<file>.prompt-blocker.bak` backup is kept. The script only manages the config entry — updating an installed package is `opencode plugin update`.

## 6. Packaging, dev tooling & CI

- **package.json** — `"type": "module"`; `exports["."] = "./src/index.ts"` (OpenCode consumes the TS source directly under Bun); `files`: `src`, `skill`, `README.md`, `LICENSE`; `peerDependencies`: `@opencode/plugin >= 2` (a devDependency copy exists for local typechecking); devDependencies `bun-types`, `typescript`, `yaml` (declared but not imported by any source file); scripts `test` (`bun test`) and `check` (`tsc --noEmit`). Distribution spec: `github:psygreg/prompt-blocker`.
- **tsconfig.json** — strict mode, ESNext target/module, `moduleResolution: "bundler"`, `verbatimModuleSyntax`, `allowImportingTsExtensions`, `types: ["bun-types"]`, `noEmit`; `include: ["src", "test"]`.
- **Dev loop** — `bun install`, `bun run check`, `bun test`. No build or publish step: installs point at the GitHub repo (or a local checkout) and OpenCode loads the source.
- **Testing policy** — no tests are committed by design (commit `ca44273` "repo: cleanup test units" removed the committed suite): per [AGENTS.md](AGENTS.md), every change is verified with a temporary harness (`*.test.ts` colocated in `src/` or under `test/` — `bun test` discovers both) and discarded once green. The detector legitimately flags this repo's own docs and skill text (they quote injection payloads), so harnesses must not assert that repo files scan clean; a stray `*.test.ts` inside a plugins directory is also recognized as spill evidence by `layout.ts`.
- **Dogfooding** — `.opencode/opencode.jsonc` loads this checkout as the plugin in `audit` mode: the repo's own docs and skill text trip the detector, and banners-only keeps the feedback without blocking development. `bun install` after cloning so the plugin's dependencies resolve.
- **CI** — none. `.github/` holds only `FUNDING.yml`.
