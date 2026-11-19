/**
 * prompt-blocker confinement: dynamic, per-session file allowlists and minimum
 * toolsets for the plugin's quarantined subagents.
 *
 * The two containment agents (document-reviewer, image-scrubber) get static
 * permission rulesets at registration, but permissions alone cannot express
 * "only the files this delegation names": the reviewer must be able to read
 * arbitrary untrusted documents, so its static rules allow every read. This
 * module adds the dynamic half. Every prompt a session receives records the
 * file paths it names as granted to that session, and a quarantined agent may
 * then touch only those files, with only its minimum toolset. Anything else is
 * a critical confinement violation: the hook that sees the attempt rejects it
 * and terminates the subagent immediately.
 *
 * Trust model: the delegation prompt is written by the orchestrating agent
 * (the parent principal), so what it names is what was "given" to the
 * subagent. Paths quoted inside the documents the subagent later reads grant
 * nothing — those only ever reach the subagent through its own tool results.
 *
 * Pure logic only: filesystem access and OpenCode APIs are injected.
 */

import { isAbsolute, join, normalize, resolve } from "node:path"
import { fileURLToPath } from "node:url"

export const REVIEWER_AGENT = "document-reviewer"
export const SCRUBBER_AGENT = "image-scrubber"

export type ConfinedAgent = typeof REVIEWER_AGENT | typeof SCRUBBER_AGENT

/** The minimum toolset for each quarantined agent; anything else terminates it. */
export const AGENT_TOOLS: Record<ConfinedAgent, readonly string[]> = {
  [REVIEWER_AGENT]: ["read"],
  [SCRUBBER_AGENT]: ["read", "image_scrub"],
}

/** Marker carried by every confinement notice, so report rewrites can detect their own text. */
export const CONFINEMENT_MARKER = "prompt-blocker CRITICAL"

const MAX_GRANT_SESSIONS = 200
const MAX_GRANTS_PER_SESSION = 64
const MAX_VIOLATIONS = 100
const MAX_EXTRACT_BYTES = 65_536

export interface Violation {
  agent: ConfinedAgent
  sessionID: string
  tool: string
  /** The path the agent tried to reach, when the violation was a file access. */
  path: string | null
  reason: "tool" | "path" | "burned"
  time: string
}

export type AccessReason = Violation["reason"]

export interface AccessDecision {
  allowed: boolean
  reason?: AccessReason
  tool: string
  path: string | null
}

// ---------------------------------------------------------------------------
// Path resolution and extraction
// ---------------------------------------------------------------------------

/** Resolve a tool- or prompt-supplied path against a base directory; normalized, or null when empty. */
export function resolveTarget(path: string, base: string | undefined): string | null {
  const trimmed = path.trim()
  if (!trimmed) return null
  const home = process.env.HOME
  const expanded =
    home && (trimmed.startsWith("~/") || trimmed.startsWith("~\\"))
      ? join(home, trimmed.slice(2))
      : trimmed
  if (isAbsolute(expanded)) return normalize(expanded)
  return resolve(base ?? process.cwd(), expanded)
}

/** True when `path` is `dir` itself or lies inside it (both normalized). */
export function underDir(path: string, dir: string): boolean {
  return path === dir || path.startsWith(dir.endsWith("/") ? dir : dir + "/")
}

function trimCandidate(candidate: string): string {
  return candidate.replace(/[.,;:!?)\]}>*"'`\\]+$/, "").trim()
}

function pushUnique(list: string[], value: string | null): void {
  if (!value || list.includes(value)) return
  list.push(value)
}

/**
 * Absolute paths named in a text, in order of appearance, deduplicated.
 * Deliberately generous: the delegation prompt is the grant, so anything that
 * plausibly names a file is granted. Covers file:// URIs, quoted paths
 * (including spaces), ~-expanded, absolute, drive-letter, and relative
 * file-like tokens ("src/foo.ts"). Prose like "and/or" or "24/7" is ignored.
 */
export function extractPaths(text: string, base: string | undefined): string[] {
  if (!text) return []
  const scanned = text.length > MAX_EXTRACT_BYTES ? text.slice(0, MAX_EXTRACT_BYTES) : text
  const out: string[] = []

  // Pass 1: file:// URIs and quoted spans that hold a path (quotes may wrap
  // spaces). Their text is then masked out, so the looser passes below never
  // carve fragments out of a path that was already granted whole.
  let rest = scanned
  for (const match of scanned.matchAll(/file:\/\/[^\s"'`<>()[\]{}]+/g)) {
    try {
      pushUnique(out, resolveTarget(fileURLToPath(match[0]), base))
      rest = rest.replace(match[0], " ".repeat(match[0].length))
    } catch {
      // Malformed URI: not a grant.
    }
  }
  for (const match of scanned.matchAll(/["'`]([^"'`\n]*[\\/][^"'`\n]*)["'`]/g)) {
    pushUnique(out, resolveTarget(trimCandidate(match[1]), base))
    rest = rest.replace(match[0], " ".repeat(match[0].length))
  }
  // Bare ~/, ./, ../, drive-letter, and absolute paths.
  for (const match of rest.matchAll(/(?<![\w:/\\])((?:~[\\/]|(?:\.{1,2})[\\/]|[A-Za-z]:[\\/]|\/)[^\s"'`,;:)\]}>]+)/g)) {
    pushUnique(out, resolveTarget(trimCandidate(match[1]), base))
  }
  // Relative file-like tokens (at least one separator, dotted final segment).
  for (const match of rest.matchAll(/(?:^|[\s("'`(])((?:\.{1,2}[\\/])?[A-Za-z0-9][A-Za-z0-9._@+-]*(?:[\\/][A-Za-z0-9._@+-]+)+)/g)) {
    const candidate = trimCandidate(match[1])
    if (candidate.includes("://")) continue // URL, not a file
    const last = candidate.split(/[\\/]/).pop() ?? ""
    if (last.includes(".")) pushUnique(out, resolveTarget(candidate, base))
  }
  return out
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

export interface Grants {
  /** Absolute paths granted, insertion-ordered, newest kept. */
  absolute: string[]
  /** Realpaths of granted files that exist, for symlink-aware matching. */
  real: string[]
  updatedAt: number
}

export function mergeGrants(
  existing: Grants | undefined,
  absolute: string[],
  real: string[],
  now: number,
): Grants {
  const paths = [...(existing?.absolute ?? [])]
  for (const path of absolute) if (!paths.includes(path)) paths.push(path)
  const reals = [...(existing?.real ?? [])]
  for (const path of real) if (!reals.includes(path)) reals.push(path)
  return {
    absolute: paths.slice(-MAX_GRANTS_PER_SESSION),
    real: reals.slice(-MAX_GRANTS_PER_SESSION),
    updatedAt: now,
  }
}

function grantedUnder(grants: Grants | undefined, dir: string): boolean {
  if (!grants) return false
  const under = (path: string) => underDir(path, dir)
  return grants.absolute.some(under) || grants.real.some(under)
}

// ---------------------------------------------------------------------------
// Access decisions
// ---------------------------------------------------------------------------

/**
 * Decide whether a quarantined agent may perform this access.
 *
 * `path` is the normalized absolute file target (read/image_scrub); `boundary`
 * is a directory boundary from an external_directory check (resource without
 * its trailing "/*"). A session with no recorded grants at all degrades to
 * permission-level confinement instead of terminating legitimate work: that
 * shape only appears after a plugin reload, and any prompt re-seeds the grant.
 */
export function checkAccess(input: {
  agent: ConfinedAgent
  tool: string
  path?: string | null
  realpath?: string | null
  boundary?: string | null
  grants?: Grants
  cleanDir?: string
  burned?: boolean
}): AccessDecision {
  const { agent, tool } = input
  const path = input.path ?? null
  if (input.burned) return { allowed: false, reason: "burned", tool, path }
  // external_directory is a guard on an access the agent is already making,
  // not a tool of its own: the boundary check below decides it.
  if (!input.boundary && !AGENT_TOOLS[agent].includes(tool)) {
    return { allowed: false, reason: "tool", tool, path }
  }
  if (input.boundary !== undefined && input.boundary !== null) {
    // No recorded grants at all: the confinement state was never seeded (a
    // plugin reload mid-run). Degrade to permission-level confinement.
    if (!input.grants) return { allowed: true, tool, path }
    const inCleanDir = !!input.cleanDir && underDir(normalize(input.boundary), input.cleanDir)
    if (inCleanDir || grantedUnder(input.grants, normalize(input.boundary))) {
      return { allowed: true, tool, path }
    }
    return { allowed: false, reason: "path", tool, path }
  }
  if (!path) return { allowed: true, tool, path }
  if (agent === SCRUBBER_AGENT && input.cleanDir && underDir(path, input.cleanDir)) {
    return { allowed: true, tool, path } // sanitized copies the scrub pipeline produced
  }
  if (input.realpath && input.grants?.real.includes(input.realpath)) return { allowed: true, tool, path }
  if (input.grants?.absolute.includes(path)) return { allowed: true, tool, path }
  if (!input.grants) return { allowed: true, tool, path }
  return { allowed: false, reason: "path", tool, path }
}

/** Extract the normalized file target from a tool call input, when the tool takes one. */
export function toolPath(tool: string, input: unknown, base: string | undefined): string | null {
  if (tool !== "read" && tool !== "image_scrub") return null
  const given = (input as { path?: unknown } | null | undefined)?.path
  if (typeof given !== "string" || given.length === 0) return null
  return resolveTarget(given, base)
}

/**
 * Interpret a permission-evaluation resource for a quarantined agent.
 * read resources are paths (location-relative inside the project, canonical
 * absolute outside); external_directory resources are directory boundaries
 * ("dir/*"). Everything else carries no file target.
 */
export function permissionTarget(
  action: string,
  resource: string | undefined,
  base: string | undefined,
): { path?: string | null; boundary?: string | null } {
  if (typeof resource !== "string" || resource.length === 0) return {}
  if (action === "external_directory") {
    const dir = resource.replace(/(?:[\\/]\*+)+[\\/]?$/, "").replace(/[\\/]+$/, "")
    return { boundary: resolveTarget(dir, base) }
  }
  if (action === "read" || action === "image_scrub") {
    return { path: resolveTarget(resource, base) }
  }
  return {}
}

// ---------------------------------------------------------------------------
// Notices
// ---------------------------------------------------------------------------

export function violationSummary(v: Violation): string {
  const what = v.path ? `\`${v.tool}\` on ${v.path}` : `the \`${v.tool}\` tool`
  const why =
    v.reason === "tool"
      ? `${what}, which is outside its minimum toolset`
      : v.reason === "path"
        ? `${what}, which was not among the files granted to it`
        : `${what} after a previous confinement violation`
  return `The ${v.agent} subagent attempted ${why}`
}

/** Error thrown inside the violating subagent, terminating its tool call. */
export function terminationError(v: Violation): string {
  return [
    `${CONFINEMENT_MARKER}: confinement violation — this subagent is terminated.`,
    `${violationSummary(v)}.`,
    `All further actions are denied and the run ends now. Report nothing except this termination.`,
  ].join("\n")
}

/** Error thrown by the model-call hook, failing the whole subagent execution. */
export function generateError(v: Violation): string {
  return [
    `${CONFINEMENT_MARKER}: this subagent was terminated for a confinement violation and performs no further work.`,
    violationSummary(v) + ".",
  ].join("\n")
}

/** Model-facing report that replaces a terminated subagent's result in its parent. */
export function confinementReport(v: Violation): string {
  return [
    `\u26d4 [prompt-blocker] SUBAGENT TERMINATED \u2014 CONFINEMENT VIOLATION (CRITICAL RISK)`,
    `${CONFINEMENT_MARKER}: ${violationSummary(v)}.`,
    `The subagent was shut down immediately and the attempt was blocked; ${v.path ? "the file was not accessed" : "the action did not run"}. Any output it had already produced is withheld as untrusted.`,
    `If this access is genuinely needed, delegate again and name the exact path in the delegation prompt. The terminated subagent session (${v.sessionID}) performs no further work.`,
  ].join("\n")
}

// ---------------------------------------------------------------------------
// Stateful confinement
// ---------------------------------------------------------------------------

export interface ConfinementDeps {
  /** Whether the plugin registers the reviewer (agent option) / scrubber (images option). */
  reviewerEnabled: boolean
  scrubberEnabled: boolean
  /** The quarantine clean directory, whose contents the scrubber may always read. */
  cleanDir?: string
  /** Best-effort realpath; null for missing or unreadable paths. */
  realpath: (path: string) => Promise<string | null>
  now: () => number
  /** Called once per new violation, for logging and shutdown side effects. */
  onViolation: (violation: Violation) => void
}

export class Confinement {
  private readonly grants = new Map<string, Grants>()
  private readonly violations = new Map<string, Violation>()

  constructor(private readonly deps: ConfinementDeps) {}

  /** The confined agent behind an agent id, when confinement applies to it. */
  confined(agent: string | undefined): ConfinedAgent | null {
    if (agent === REVIEWER_AGENT && this.deps.reviewerEnabled) return REVIEWER_AGENT
    if (agent === SCRUBBER_AGENT && this.deps.scrubberEnabled) return SCRUBBER_AGENT
    return null
  }

  /**
   * Grant a session the paths its prompt names. Called for every prompt of
   * every session; sessions that receive a prompt with no paths end up with
   * an empty grant set, which confines them to nothing rather than leaving
   * them unrestricted.
   */
  async grant(sessionID: string, text: string, base?: string): Promise<void> {
    const paths = extractPaths(text, base)
    const real: string[] = []
    for (const resolved of await Promise.all(paths.map((path) => this.deps.realpath(path).catch(() => null)))) {
      if (resolved) real.push(resolved)
    }
    const existing = this.grants.get(sessionID)
    this.grants.set(sessionID, mergeGrants(existing, paths, real, this.deps.now()))
    while (this.grants.size > MAX_GRANT_SESSIONS) {
      const oldest = this.grants.keys().next().value
      if (oldest === undefined) break
      this.grants.delete(oldest)
    }
  }

  /**
   * Check a tool call by a quarantined agent. Returns the violation to
   * terminate on, or null when the call may proceed.
   */
  async checkToolCall(input: {
    sessionID: string
    agent: string | undefined
    tool: string
    toolInput?: unknown
    base?: string
  }): Promise<Violation | null> {
    const agent = this.confined(input.agent)
    if (!agent) return null
    const path = toolPath(input.tool, input.toolInput, input.base)
    const decision = checkAccess({
      agent,
      tool: input.tool,
      path,
      realpath: await this.safeRealpath(path),
      grants: this.grants.get(input.sessionID),
      cleanDir: this.deps.cleanDir,
      burned: this.violations.has(input.sessionID),
    })
    if (decision.allowed) return null
    return this.record(agent, input.sessionID, decision)
  }

  /**
   * Clamp a permission evaluation for a quarantined agent. Returns the
   * violation to deny with, or null to leave the evaluation untouched.
   */
  async clampPermission(input: {
    sessionID: string
    agent: string | undefined
    action: string
    resources: readonly string[]
    base?: string
  }): Promise<Violation | null> {
    const agent = this.confined(input.agent)
    if (!agent) return null
    // One resource per call is the shape read/external_directory asserts use;
    // multi-resource calls are not path checks and fall through to the toolset rule.
    const resource = input.resources.length === 1 ? input.resources[0] : undefined
    const target = permissionTarget(input.action, resource, input.base)
    const decision = checkAccess({
      agent,
      tool: input.action,
      path: target.path ?? null,
      realpath: await this.safeRealpath(target.path ?? null),
      boundary: target.boundary ?? null,
      grants: this.grants.get(input.sessionID),
      cleanDir: this.deps.cleanDir,
      burned: this.violations.has(input.sessionID),
    })
    if (decision.allowed) return null
    return this.record(agent, input.sessionID, decision)
  }

  /**
   * Burn a quarantined session on a permission denial it received from the
   * static ruleset (which never reaches the evaluate hook). User rejections
   * and prompt-blocker's own denials are not confinement violations.
   */
  observeDeniedCall(input: {
    sessionID: string
    agent: string | undefined
    tool: string
    message: string | undefined
    toolInput?: unknown
    base?: string
  }): Violation | null {
    const agent = this.confined(input.agent)
    if (!agent) return null
    if (this.violations.has(input.sessionID)) return null
    const message = input.message ?? ""
    if (!message.startsWith("Permission denied:")) return null
    const decision = checkAccess({
      agent,
      tool: input.tool,
      path: toolPath(input.tool, input.toolInput, input.base),
      grants: this.grants.get(input.sessionID),
      cleanDir: this.deps.cleanDir,
      burned: false,
    })
    if (decision.allowed) return null
    return this.record(agent, input.sessionID, { ...decision, reason: "tool" })
  }

  /** The violation recorded for a child session, for parent-side reporting. */
  violationOf(sessionID: string | undefined | null): Violation | undefined {
    if (!sessionID) return undefined
    return this.violations.get(sessionID)
  }

  private async safeRealpath(path: string | null | undefined): Promise<string | null> {
    if (!path) return null
    try {
      return await this.deps.realpath(path)
    } catch {
      return null
    }
  }

  private record(agent: ConfinedAgent, sessionID: string, decision: AccessDecision): Violation {
    const existing = this.violations.get(sessionID)
    if (existing) return existing
    const violation: Violation = {
      agent,
      sessionID,
      tool: decision.tool,
      path: decision.path,
      reason: decision.reason ?? "tool",
      time: new Date(this.deps.now()).toISOString(),
    }
    this.violations.set(sessionID, violation)
    while (this.violations.size > MAX_VIOLATIONS) {
      const oldest = this.violations.keys().next().value
      if (oldest === undefined) break
      this.violations.delete(oldest)
    }
    this.deps.onViolation(violation)
    return violation
  }
}
