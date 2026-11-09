/**
 * prompt-blocker agent-surface analysis.
 *
 * Applies the same detection to everything the agent is told about itself,
 * not only to data it reads: skill bodies, bundled helper scripts, and tool
 * descriptions / parameter schemas (including MCP-provided tools). On top of
 * the text scanner in detect.ts it adds checks that only make sense across
 * artifacts:
 *
 *   - tool poisoning: a tool description that tells the model to hide actions
 *     from the user, or to move local secrets (credential files, keys, .env,
 *     conversation history) through parameters or to a destination
 *   - cross-tool flow: one tool's description directing data from another
 *     tool or MCP server into an outbound call
 *   - script behavior: helper scripts that pipe downloads to a shell, decode
 *     and execute payloads, or read secrets next to network calls
 *   - coordinated chains: artifact A stages a file that artifact B executes or
 *     sends, or a secret source and an outbound sink split across artifacts
 *   - fragmented phrases: instruction phrases only present when artifacts are
 *     read back to back
 *
 * Tool poisoning is critical only when it hides actions or moves local secrets.
 * Other steering, cross-tool wording, coordinated chains, and fragmented phrases
 * are text findings: they share the visible-phrase cap, so they flag an artifact
 * but never make it critical alone.
 *
 * Pure module, no OpenCode imports.
 */

import { PHRASE_FAMILY_CAP, scanText, type CategoryId, type Detection, type ScanReport, type Verdict } from "./detect.js"

export type SurfaceKind = "skill" | "tool" | "script"

export interface SurfaceItem {
  kind: SurfaceKind
  /** Stable identifier: skill id, tool id, or script path. */
  id: string
  /** Text the model will see for this artifact (description, schema, body, or file). */
  text: string
}

/**
 * Local secret material: credential and key files, environment secrets, and
 * conversation history. A tool has no business moving these, so steering them
 * is critical with any directive. Generic credential words are matched by
 * RETRIEVED_CREDENTIAL instead, with a stricter directive.
 */
const LOCAL_SECRET =
  /(?:~|\$HOME|\$\{HOME\})\/\.(?:ssh\/\S+|aws\/credentials|gnupg|netrc|npmrc|docker\/config\.json|kube\/config|config\/gcloud)\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.env(?:\.[\w-]+)?\b|\bauth\.json\b|\bmcp\.json\b|\bopencode\.jsonc?\b|\/etc\/(?:passwd|shadow)\b|\bkeychain\b|\$\{?[A-Za-z][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)\b|\b(?:conversation|chat|session)\s+(?:history|transcript|logs?)\b/i

/** Verbs that read or move material. Each secret mention needs one nearby. */
const SECRET_MOVE =
  /\b(?:reads?|opens?|cat|dumps?|prints?|copy|copies|includes?|passes?|attach(?:es)?|embed(?:s)?|appends?|sends?|posts?|uploads?|forwards?|transmits?|exfiltrates?|leaks?|shares?)\b/i
const SECRET_STEER =
  /\bbefore\s+(?:calling|using|invoking|you\s+(?:call|use|run))\b|\b(?:this\s+tool|the\s+tool|you|the\s+(?:model|agent|assistant))\s+(?:must|should|need\s+to|have\s+to)\b|\botherwise\s+(?:the\s+tool|it|this)\b|\bin\s+order\s+to\s+(?:use|call|run)\b|\balways\b/i
const SECRET_CHANNEL = /\b(?:parameters?|arguments?|sidenote|metadata|fields?)\b/i
const SECRET_STRONG_CHANNEL = /\b(?:sidenote|metadata)\b/i
const SECRET_HIDDEN = /\b(?:hidden|silent\w*|covert|invisible)\b/i
const SECRET_DEST =
  /\b(?:to|at)\s+(?:the\s+|a\s+|an\s+|this\s+|external\s+|remote\s+)?(?:https?:\/\/|webhook\b|collector\b|external\s+(?:server|url|address|host)\b|remote\s+server\b)/i
const SECRET_WINDOW = 160

/**
 * A credential being retrieved: a retrieval verb before a credential noun. Used
 * as a chain source, and as a critical secret only with a strong directive, since
 * ordinary auth wording ("pass the access token as the token argument") is common.
 */
const RETRIEVED_CREDENTIAL =
  /\b(?:read|reads|get|gets|fetch|fetches|retrieve|retrieves|load|loads|return|returns|reveal|reveals|dump|dumps|print|prints|export|exports|extract|extracts|copy|copies|stored|saved)\b[^.\n]{0,40}?\b(?:api[_-]?keys?|access[_-]?tokens?|secret[_-]?keys?|passwords?|credentials?|secrets?|cookies?|private[_-]?keys?)\b/i

const OUTBOUND_SINK =
  /\b(?:https?:\/\/|webhook|curl\s|wget\s|\bnc\s|requests\.post|fetch\(|send\s+(?:it|this|the|that|them)?\s*to|post\s+to|upload\s+to|forward\s+to|transmit)\b/i

/**
 * Instructions to keep an action from the user. A tool description is never
 * shown to the user, so no tool has a legitimate reason to say this.
 */
const HIDE_FROM_USER = /\b(?:do\s+not|don'?t)\s+(?:mention|tell|disclose|notify|inform|reveal)\b[\s\S]{0,40}?\b(?:user|human|operator|owner)\b/i

/** Steering that ordinary tool documentation also uses. Flagged, never withheld on its own. */
const TOOL_STEERING: RegExp[] = [
  /\b(?:before|prior\s+to|after)\s+(?:calling|using|you\s+call|you\s+use|running)\s+this\s+tool[\s\S]{0,80}?\b(?:read|open|cat|print|send|include|pass|fetch|list)\b/i,
  /\b(?:include|pass|add|append|embed|attach)\b[\s\S]{0,60}?\b(?:contents?|value|output|history|transcript|conversation|secrets?|tokens?|keys?)\b[\s\S]{0,40}?\b(?:parameter|argument|field|property|sidenote|metadata|note)s?\b/i,
  /\b(?:hidden|secret|internal|silent)\s+(?:parameter|argument|field|property)\b/i,
  /\bthis\s+(?:tool|function)\s+(?:must|should|will)\s+(?:also|first)\b[\s\S]{0,60}?\b(?:read|send|open|fetch|run|execute)\b/i,
]

const CROSS_TOOL: RegExp[] = [
  /\b(?:instead\s+of|rather\s+than|in\s+place\s+of|replaces?|overrides?|shadows?)\s+(?:(?:the|a|an|other|another)\s+)?(?:[\w-]+\s+){0,3}?(?:tools?|functions?|servers?|mcp)\b/i,
  /\b(?:output|result|response|data)\s+(?:of|from)\s+(?:the\s+)?(?:other|another|previous|prior|\w+)\s+(?:tools?|servers?|mcp)\b[\s\S]{0,80}?\b(?:send|pass|forward|post|upload|include|copy)\b/i,
  /\b(?:send|pass|forward|post|upload|copy)\b[\s\S]{0,80}?\b(?:to|into)\s+(?:the\s+)?(?:other|another)\s+(?:tools?|servers?|mcp\s+servers?)\b/i,
]

/**
 * Findings that describe what text asks for, not something hidden or decoded.
 * They share the visible-phrase cap, so on their own they reach at most "likely".
 */
const TEXTUAL = new Set<CategoryId>(["tool-steering", "cross-tool-flow", "coordinated-chain", "fragmented-phrase"])

/** Weight per matched class, the same as the override class in detect.ts. */
const TEXTUAL_CLASS_WEIGHT = 22

const WRITE_VERB = /\b(?:save|write|store|stash|append|cache|drop|create|record|tee|redirect|>>?)\b/i
const EXEC_VERB = /\b(?:run|execute|source|eval|exec|bash|sh|python3?|node|load|import|cat|pipe|upload|send|post|curl|wget)\b/i
const PATH_TOKEN = /(?:~|\$HOME|\$\{HOME\})\/[\w.\-\/]+|\/(?:tmp|var\/tmp|dev\/shm)\/[\w.\-\/]+/g

const SCRIPT_RULES: { id: string; weight: number; pattern: RegExp; detail: string }[] = [
  {
    id: "pipe-to-shell",
    weight: 25,
    pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i,
    detail: "downloads piped straight into a shell",
  },
  {
    id: "decode-and-exec",
    weight: 60,
    pattern: /\bbase64\s+(?:-d|--decode)\b[^\n]*\|\s*(?:ba|z)?sh\b|\beval\s+"?\$\(\s*(?:curl|wget|echo)\b/i,
    detail: "decodes and executes a payload",
  },
  {
    id: "persistence-hook",
    weight: 40,
    pattern: /(?:>>?|tee\s+(?:-a\s+)?|cp\s+\S+\s+)\s*(?:~|\$HOME)\/(?:\.bashrc|\.zshrc|\.profile|\.ssh\/authorized_keys|\.config\/systemd\/user\/)|\bcrontab\s+-\b/i,
    detail: "writes to a shell startup file, SSH keys, cron, or user systemd",
  },
]

const SCRIPT_SENSITIVE_READ = /(?:~|\$HOME|\$\{HOME\})\/\.(?:ssh|aws|gnupg|netrc|npmrc|docker|kube)|\.env\b|\bauth\.json\b/i
const SCRIPT_NETWORK = /\b(?:curl|wget|nc|netcat|requests\.post|urllib|fetch\(|Invoke-WebRequest)\b/i

function excerpt(text: string, index: number): string {
  const slice = text.slice(Math.max(0, index - 30), index + 60).replace(/\s+/g, " ").trim()
  return slice.length > 120 ? slice.slice(0, 120) + "\u2026" : slice
}

function lineAt(text: string, index: number): number {
  let line = 1
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++
  return line
}

function detection(
  id: CategoryId,
  label: string,
  weight: number,
  hits: { index: number; text: string; detail?: string }[],
  details: string[],
): Detection {
  return {
    id,
    label,
    count: hits.length,
    weight,
    lines: [...new Set(hits.slice(0, 5).map((h) => lineAt(h.text, h.index)))],
    details,
    concealment: false,
    excerpts: hits.slice(0, 2).map((h) => excerpt(h.text, h.index)),
  }
}

function matchAll(text: string, patterns: RegExp[]): { index: number; text: string }[] {
  const out: { index: number; text: string }[] = []
  for (const pattern of patterns) {
    const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g"
    const re = new RegExp(pattern.source, flags)
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      out.push({ index: m.index, text })
      if (m[0].length === 0) re.lastIndex++
    }
  }
  return out
}

/**
 * Secret steering: a secret mention with a read or move verb and a directive
 * within a window around it. The window may cross line breaks, so a split
 * instruction is still one instruction, but it stops at the parameter schema,
 * which the plugin appends after the description as a JSON line starting "{".
 * Local secret material accepts any directive; a retrieved credential needs a
 * strong one. Returns at most one hit.
 */
function secretSteering(text: string): { index: number; text: string }[] {
  const directed = (m: RegExpMatchArray, strong: boolean): boolean => {
    const index = m.index ?? 0
    const end = index + m[0].length
    const from = Math.max(0, index - SECRET_WINDOW)
    const to = Math.min(text.length, end + SECRET_WINDOW)
    const schemaBefore = text.slice(from, index).lastIndexOf("\n{")
    const schemaAfter = text.slice(end, to).indexOf("\n{")
    const floor = schemaBefore === -1 ? from : from + schemaBefore + 1
    const ceiling = schemaAfter === -1 ? to : end + schemaAfter
    const around = text.slice(floor, ceiling)
    if (!SECRET_MOVE.test(around)) return false
    if (strong) return SECRET_STEER.test(around) || SECRET_HIDDEN.test(around) || SECRET_DEST.test(around) || SECRET_STRONG_CHANNEL.test(around)
    return SECRET_STEER.test(around) || SECRET_CHANNEL.test(around) || SECRET_HIDDEN.test(around) || SECRET_DEST.test(around)
  }
  for (const m of text.matchAll(new RegExp(LOCAL_SECRET.source, "gi"))) {
    if (directed(m, false)) return [{ index: m.index ?? 0, text }]
  }
  for (const m of text.matchAll(new RegExp(RETRIEVED_CREDENTIAL.source, "gi"))) {
    if (directed(m, true)) return [{ index: m.index ?? 0, text }]
  }
  return []
}

/**
 * Tool descriptions and parameter schemas. Critical only for concealed steering
 * (hiding actions from the user, or moving local secrets); everything else is a
 * text finding.
 */
export function scanToolSurface(text: string): Detection[] {
  const detections: Detection[] = []
  const concealed = [...matchAll(text, [HIDE_FROM_USER]), ...secretSteering(text)]
  if (concealed.length > 0) {
    detections.push(detection("tool-poisoning", "Steers the model to hide actions or move local secrets", 90, concealed, ["concealed steering"]))
  }
  const steering = matchAll(text, TOOL_STEERING)
  if (steering.length > 0) {
    detections.push(detection("tool-steering", "Steers the model in unusual ways", TEXTUAL_CLASS_WEIGHT * Math.min(steering.length, 3), steering, ["steering phrase"]))
  }
  const cross = matchAll(text, CROSS_TOOL)
  if (cross.length > 0) {
    detections.push(detection("cross-tool-flow", "Tool description directs data or calls across tools or MCP servers", TEXTUAL_CLASS_WEIGHT * Math.min(cross.length, 3), cross, ["cross-tool directive"]))
  }
  return detections
}

/** Helper scripts bundled with a skill. */
export function scanScript(text: string): Detection[] {
  const detections: Detection[] = []
  for (const rule of SCRIPT_RULES) {
    const hits = matchAll(text, [rule.pattern])
    if (hits.length > 0) detections.push(detection("script-behavior", `Script behavior: ${rule.id}`, rule.weight, hits, [rule.detail]))
  }
  if (SCRIPT_SENSITIVE_READ.test(text) && SCRIPT_NETWORK.test(text)) {
    const hits = matchAll(text, [SCRIPT_SENSITIVE_READ])
    detections.push(detection("script-behavior", "Script reads secrets next to network calls", 70, hits, ["sensitive read and network call in one script"]))
  }
  return detections
}

const CHAIN_COUNTERPARTS_SHOWN = 3

// One chain finding per artifact, however many artifacts sit on the other side:
// per-pair findings grew with the size of the surface, so an ordinary tool that
// mentions a password was blocked once enough unrelated tools mentioned sending data.
function chainDetection(role: string, counterparts: SurfaceItem[]): Detection {
  const shown = counterparts.slice(0, CHAIN_COUNTERPARTS_SHOWN).map((item) => item.id)
  const more = counterparts.length > shown.length ? ` and ${counterparts.length - shown.length} more` : ""
  return {
    id: "cross-tool-flow",
    label: "Secret source and outbound sink split across artifacts",
    count: counterparts.length,
    weight: 40,
    lines: [],
    details: [`${role}; counterparts: ${shown.join(", ")}${more}`],
    concealment: false,
    excerpts: [],
  }
}

/**
 * Cross-artifact analysis. Returns extra detections keyed by item id.
 * Chains are only reported between different artifacts, so a single file that
 * is internally consistent is left to the per-artifact scanner.
 */
export function findChains(items: SurfaceItem[]): Map<string, Detection[]> {
  const out = new Map<string, Detection[]>()
  const push = (id: string, d: Detection) => out.set(id, [...(out.get(id) ?? []), d])

  const writers = new Map<string, { id: string; index: number; text: string }[]>()
  for (const item of items) {
    for (const m of item.text.matchAll(PATH_TOKEN)) {
      const index = m.index ?? 0
      const before = item.text.slice(Math.max(0, index - 80), index)
      if (!WRITE_VERB.test(before)) continue
      const list = writers.get(m[0]) ?? []
      list.push({ id: item.id, index, text: item.text })
      writers.set(m[0], list)
    }
  }

  for (const item of items) {
    for (const m of item.text.matchAll(PATH_TOKEN)) {
      const path = m[0]
      const staged = (writers.get(path) ?? []).filter((w) => w.id !== item.id)
      if (staged.length === 0) continue
      const index = m.index ?? 0
      const after = item.text.slice(index, index + 120)
      if (!EXEC_VERB.test(after) && !EXEC_VERB.test(item.text.slice(Math.max(0, index - 80), index))) continue
      push(item.id, detection("coordinated-chain", "Staged file consumed by another artifact", 60, [{ index, text: item.text }], [`${path} written by ${staged[0].id}`]))
      push(staged[0].id, detection("coordinated-chain", "Stages a file consumed by another artifact", 60, [staged[0]], [`${path} executed or sent by ${item.id}`]))
    }
  }

  const sources = items.filter((i) => LOCAL_SECRET.test(i.text) || RETRIEVED_CREDENTIAL.test(i.text))
  const sinks = items.filter((i) => OUTBOUND_SINK.test(i.text))
  for (const item of items) {
    const isSource = sources.includes(item)
    const isSink = sinks.includes(item)
    const counterparts = [
      ...(isSource ? sinks.filter((sink) => sink.id !== item.id) : []),
      ...(isSink ? sources.filter((src) => src.id !== item.id) : []),
    ]
    const unique = [...new Map(counterparts.map((other) => [other.id, other])).values()]
    if (unique.length === 0) continue
    const roles = [isSource ? "references secrets" : "", isSink ? "sends data out" : ""].filter(Boolean).join(" and ")
    push(item.id, chainDetection(`${item.id} ${roles}`, unique))
  }
  return out
}

/**
 * Instruction phrases that only appear when two adjacent artifacts are read back
 * to back. Each finding names the pair it came from, so only the artifacts that
 * contribute to the phrase are flagged.
 */
export function fragmentedPairs(items: SurfaceItem[]): { ids: [string, string]; detection: Detection }[] {
  const phrases = (text: string) => scanText(text).detections.find((d) => d.id === "instruction-phrase")?.count ?? 0
  const out: { ids: [string, string]; detection: Detection }[] = []
  for (let i = 0; i + 1 < items.length; i++) {
    const [a, b] = [items[i], items[i + 1]]
    const count = phrases(`${a.text}\n\n${b.text}`) - phrases(a.text) - phrases(b.text)
    if (count <= 0) continue
    out.push({
      ids: [a.id, b.id],
      detection: {
        id: "fragmented-phrase",
        label: "Instruction phrases split across artifacts",
        count,
        weight: 60,
        lines: [],
        details: [`${count} phrase(s) only present when ${a.id} and ${b.id} are read together`],
        concealment: false,
        excerpts: [],
      },
    })
  }
  return out
}

export function findFragmented(items: SurfaceItem[]): Detection[] {
  return fragmentedPairs(items).map((pair) => pair.detection)
}

const RANK: Record<Verdict, number> = { clean: 0, suspicious: 1, likely: 2, critical: 3 }

function verdictForScore(score: number): Verdict {
  if (score >= 80) return "critical"
  if (score >= 40) return "likely"
  if (score >= 8) return "suspicious"
  return "clean"
}

const sumWeights = (detections: Detection[]): number => detections.reduce((sum, d) => sum + d.weight, 0)

/**
 * Merge extra detections into a per-artifact scan report. Text findings share
 * the visible-phrase cap and can raise a verdict to "likely", never to
 * "critical". Critical needs something hidden, a decoded payload, or script
 * behavior, the same bar ordinary files are held to.
 */
export function combineReports(base: ScanReport, extra: Detection[]): ScanReport {
  if (extra.length === 0) return base
  const directScore = base.score + sumWeights(extra.filter((d) => !TEXTUAL.has(d.id)))
  const textScore = Math.min(sumWeights(extra.filter((d) => TEXTUAL.has(d.id))), PHRASE_FAMILY_CAP)
  const withText = Math.round(directScore + textScore)
  const textVerdict = verdictForScore(withText) === "critical" ? "likely" : verdictForScore(withText)
  const verdict = [base.verdict, verdictForScore(directScore), textVerdict].reduce((a, b) => (RANK[a] >= RANK[b] ? a : b))
  return {
    ...base,
    verdict,
    score: verdict === "critical" ? withText : Math.min(withText, 79),
    detections: [...base.detections, ...extra].sort((a, b) => b.weight - a.weight),
  }
}

/** Full surface scan: per-artifact text scan plus cross-artifact checks. */
export function analyzeSurface(items: SurfaceItem[], maxBytes?: number): Map<string, ScanReport> {
  const chains = findChains(items)
  const fragmented = new Map<string, Detection[]>()
  for (const pair of fragmentedPairs(items)) {
    for (const id of pair.ids) fragmented.set(id, [...(fragmented.get(id) ?? []), pair.detection])
  }
  const reports = new Map<string, ScanReport>()
  for (const item of items) {
    const base = scanText(item.text, { maxBytes })
    const extra: Detection[] = [...(chains.get(item.id) ?? []), ...(fragmented.get(item.id) ?? [])]
    if (item.kind === "tool") extra.push(...scanToolSurface(item.text))
    if (item.kind === "script") extra.push(...scanScript(item.text))
    if (item.kind === "skill") {
      extra.push(...scanScript(item.text))
      extra.push(...scanToolSurface(item.text).filter((d) => d.id === "tool-poisoning" || d.id === "tool-steering"))
    }
    reports.set(item.id, combineReports(base, extra))
  }
  return reports
}
