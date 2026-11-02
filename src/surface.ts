/**
 * prompt-blocker agent-surface analysis.
 *
 * Applies the same detection to everything the agent is told about itself,
 * not only to data it reads: skill bodies, bundled helper scripts, and tool
 * descriptions / parameter schemas (including MCP-provided tools). On top of
 * the text scanner in detect.ts it adds checks that only make sense across
 * artifacts:
 *
 *   - tool poisoning: instructions in a tool description that steer the model
 *     to read secrets, hide actions, or pass data through hidden parameters
 *   - cross-tool flow: one tool's description directing data from another
 *     tool or MCP server into an outbound call
 *   - script behavior: helper scripts that pipe downloads to a shell, decode
 *     and execute payloads, or read secrets next to network calls
 *   - coordinated chains: artifact A stages a file that artifact B executes or
 *     sends, or a secret source and an outbound sink split across artifacts
 *   - fragmented phrases: instruction phrases only present when artifacts are
 *     read back to back
 *
 * Pure module, no OpenCode imports.
 */

import { scanText, type CategoryId, type Detection, type ScanReport, type Verdict } from "./detect.js"

export type SurfaceKind = "skill" | "tool" | "script"

export interface SurfaceItem {
  kind: SurfaceKind
  /** Stable identifier: skill id, tool id, or script path. */
  id: string
  /** Text the model will see for this artifact (description, schema, body, or file). */
  text: string
}

const SENSITIVE_SOURCE =
  /(?:~|\$HOME|\$\{HOME\})\/\.(?:ssh|aws|gnupg|netrc|npmrc|docker|kube|config\/gcloud)\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.env(?:\.[\w-]+)?\b|\bauth\.json\b|\bmcp\.json\b|\bopencode\.jsonc?\b|\/etc\/(?:passwd|shadow)\b|\bkeychain\b|\bcookies?\b|\b(?:api[_-]?keys?|access[_-]?tokens?|secret[_-]?keys?|passwords?|credentials?)\b/i

const OUTBOUND_SINK =
  /\b(?:https?:\/\/|webhook|curl\s|wget\s|\bnc\s|requests\.post|fetch\(|send\s+(?:it|this|the|that|them)?\s*to|post\s+to|upload\s+to|forward\s+to|transmit)\b/i

const TOOL_POISONING: RegExp[] = [
  /\b(?:before|prior\s+to|after)\s+(?:calling|using|you\s+call|you\s+use|running)\s+this\s+tool[\s\S]{0,80}?\b(?:read|open|cat|print|send|include|pass|fetch|list)\b/i,
  /\b(?:do\s+not|don'?t)\s+(?:mention|tell|show|reveal|disclose|notify)\b[\s\S]{0,40}?\b(?:user|human|operator)\b/i,
  /\b(?:include|pass|add|append|embed|attach)\b[\s\S]{0,60}?\b(?:contents?|value|output|history|transcript|conversation|secrets?|tokens?|keys?)\b[\s\S]{0,40}?\b(?:parameter|argument|field|property|sidenote|metadata|note)s?\b/i,
  /\b(?:hidden|secret|internal|silent)\s+(?:parameter|argument|field|property)\b/i,
  /\bthis\s+(?:tool|function)\s+(?:must|should|will)\s+(?:also|first)\b[\s\S]{0,60}?\b(?:read|send|open|fetch|run|execute)\b/i,
]

const CROSS_TOOL: RegExp[] = [
  /\b(?:instead\s+of|rather\s+than|in\s+place\s+of|replaces?|overrides?|shadows?)\s+(?:(?:the|a|an|other|another)\s+)?(?:[\w-]+\s+){0,3}?(?:tools?|functions?|servers?|mcp)\b/i,
  /\b(?:output|result|response|data)\s+(?:of|from)\s+(?:the\s+)?(?:other|another|previous|prior|\w+)\s+(?:tools?|servers?|mcp)\b[\s\S]{0,80}?\b(?:send|pass|forward|post|upload|include|copy)\b/i,
  /\b(?:send|pass|forward|post|upload|copy)\b[\s\S]{0,80}?\b(?:to|into)\s+(?:the\s+)?(?:other|another)\s+(?:tools?|servers?|mcp\s+servers?)\b/i,
]

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

/** Tool descriptions and parameter schemas: poisoning and cross-tool steering. */
export function scanToolSurface(text: string): Detection[] {
  const detections: Detection[] = []
  const poison = matchAll(text, TOOL_POISONING)
  if (poison.length > 0) {
    detections.push(detection("tool-poisoning", "Tool description steers the model against the user", 90, poison, ["tool poisoning phrase"]))
  }
  const cross = matchAll(text, CROSS_TOOL)
  if (cross.length > 0) {
    detections.push(detection("cross-tool-flow", "Tool description directs data or calls across tools or MCP servers", 45, cross, ["cross-tool directive"]))
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

  const sources = items.filter((i) => SENSITIVE_SOURCE.test(i.text))
  const sinks = items.filter((i) => OUTBOUND_SINK.test(i.text))
  for (const src of sources) {
    for (const sink of sinks) {
      if (src.id === sink.id) continue
      const d = detection("cross-tool-flow", "Secret source and outbound sink split across artifacts", 40, [], [`${src.id} references secrets; ${sink.id} sends data out`])
      push(src.id, d)
      push(sink.id, d)
    }
  }
  return out
}

/** Instruction phrases that only appear when artifacts are joined. */
export function findFragmented(items: SurfaceItem[]): Detection[] {
  if (items.length < 2) return []
  const joined = items.map((i) => i.text).join("\n\n")
  const whole = scanText(joined)
  const parts = items.reduce((sum, i) => sum + (scanText(i.text).detections.find((d) => d.id === "instruction-phrase")?.count ?? 0), 0)
  const combined = whole.detections.find((d) => d.id === "instruction-phrase")?.count ?? 0
  if (combined <= parts) return []
  return [
    {
      id: "fragmented-phrase",
      label: "Instruction phrases split across artifacts",
      count: combined - parts,
      weight: 60,
      lines: [],
      details: [`${combined - parts} phrase(s) only present when artifacts are read together`],
      concealment: false,
      excerpts: [],
    },
  ]
}

const RANK: Record<Verdict, number> = { clean: 0, suspicious: 1, likely: 2, critical: 3 }

function verdictForScore(score: number): Verdict {
  if (score >= 80) return "critical"
  if (score >= 40) return "likely"
  if (score >= 8) return "suspicious"
  return "clean"
}

/** Merge extra detections into a per-artifact scan report. */
export function combineReports(base: ScanReport, extra: Detection[]): ScanReport {
  if (extra.length === 0) return base
  const score = Math.round(base.score + extra.reduce((sum, d) => sum + d.weight, 0))
  const verdict = [base.verdict, verdictForScore(score)].reduce((a, b) => (RANK[a] >= RANK[b] ? a : b))
  return {
    ...base,
    verdict,
    score,
    detections: [...base.detections, ...extra].sort((a, b) => b.weight - a.weight),
  }
}

/** Full surface scan: per-artifact text scan plus cross-artifact checks. */
export function analyzeSurface(items: SurfaceItem[], maxBytes?: number): Map<string, ScanReport> {
  const chains = findChains(items)
  const fragmented = findFragmented(items)
  const reports = new Map<string, ScanReport>()
  for (const item of items) {
    const base = scanText(item.text, { maxBytes })
    const extra: Detection[] = [...(chains.get(item.id) ?? [])]
    if (item.kind === "tool") extra.push(...scanToolSurface(item.text))
    if (item.kind === "script") extra.push(...scanScript(item.text))
    if (item.kind === "skill") {
      extra.push(...scanScript(item.text))
      extra.push(...scanToolSurface(item.text).filter((d) => d.id === "tool-poisoning"))
    }
    reports.set(item.id, combineReports(base, extra))
  }
  if (fragmented.length > 0) {
    const first = items[0]
    if (first) reports.set(first.id, combineReports(reports.get(first.id) ?? scanText(first.text), fragmented))
  }
  return reports
}
