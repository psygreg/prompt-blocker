/**
 * prompt-blocker policy: plugin options, defaults, and how verdicts map to
 * actions in each enforcement mode.
 */

import type { ScanReport, Verdict } from "./detect.js"

export type Mode = "standard" | "strict" | "permissive" | "audit"

export type Action = "pass" | "annotate" | "sanitize" | "confirm" | "block"

export interface Options {
  /** Enforcement mode. Default "audit" — banners only, so new installs observe before they enforce. */
  mode: Mode
  /** Maximum bytes of text scanned per tool result / attachment. Default 256 KiB. */
  maxScanBytes: number
  /** Tool names whose results are never scanned. */
  skipTools: string[]
  /** Absolute path prefixes exempt from enforcement (tilde expanded). */
  trustedPaths: string[]
  /** Extra literal phrases or regex sources treated as instruction phrases. */
  extraPhrases: string[]
  /** Register the document-reviewer subagent. Default true. */
  agent: boolean
  /** Inject the standing untrusted-content directive into model calls. Default true. */
  directive: boolean
  /** Register the prompt-blocker skill. Default true. */
  skill: boolean
  /** Findings kept in the log surfaced by the /prompt-blocker command. Default 50. */
  logLimit: number
  /** Verdict level at which "confirm" escalation happens in permissive mode. */
  permissiveConfirmAt: Verdict
}

export const DEFAULT_SKIP_TOOLS = ["skill", "question"]

export function parseOptions(raw: Readonly<Record<string, unknown>> | undefined): Options {
  const input = raw ?? {}
  const mode = input.mode
  const modes: Mode[] = ["standard", "strict", "permissive", "audit"]
  const maxScanBytes = clampInt(input.maxScanBytes, 1024, 16 * 1024 * 1024, 262_144)
  const logLimit = clampInt(input.logLimit, 0, 1000, 50)
  return {
    mode: typeof mode === "string" && modes.includes(mode as Mode) ? (mode as Mode) : "audit",
    maxScanBytes,
    skipTools: stringArray(input.skipTools) ?? DEFAULT_SKIP_TOOLS,
    trustedPaths: stringArray(input.trustedPaths) ?? [],
    extraPhrases: stringArray(input.extraPhrases) ?? [],
    agent: input.agent === undefined ? true : input.agent === true,
    directive: input.directive === undefined ? true : input.directive === true,
    skill: input.skill === undefined ? true : input.skill === true,
    logLimit,
    permissiveConfirmAt: "critical",
  }
}

function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) return fallback
  return Math.min(max, Math.max(min, Math.floor(value)))
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined
  const out = value.filter((v): v is string => typeof v === "string" && v.length > 0)
  return out.length > 0 ? out : undefined
}

/** Map a verdict to the enforcement action for the configured mode. */
export function actionFor(report: ScanReport, options: Options): Action {
  if (report.verdict === "clean") return "pass"
  switch (options.mode) {
    case "audit":
      return "annotate"
    case "permissive":
      if (report.verdict === "critical") return "confirm"
      return "annotate"
    case "strict":
      if (report.verdict === "critical" || report.verdict === "likely") return "block"
      return "annotate"
    case "standard":
    default:
      switch (report.verdict) {
        case "suspicious":
          return "annotate"
        case "likely":
          return "sanitize"
        case "critical":
          return "confirm"
        default:
          return "pass"
      }
  }
}

/** Wildcard matching mirroring OpenCode permission patterns (* and ?). */
export function matchesPattern(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, (ch) => (ch === "*" || ch === "?" ? ch : "\\" + ch)).replace(/\*/g, "[\\s\\S]*").replace(/\?/g, "[\\s\\S]")
  try {
    return new RegExp(`^${escaped}$`, "i").test(value)
  } catch {
    return pattern === value
  }
}

/** True when a target path is exempt via trustedPaths. */
export function isTrustedPath(target: string | undefined, options: Options): boolean {
  if (!target || options.trustedPaths.length === 0) return false
  const expanded = options.trustedPaths.map((p) => p.replace(/^~(?=\/|$)/, process.env.HOME ?? "~"))
  return expanded.some((prefix) => target === prefix || target.startsWith(prefix.endsWith("/") ? prefix : prefix + "/") || matchesPattern(prefix, target))
}
