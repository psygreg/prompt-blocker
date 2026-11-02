#!/usr/bin/env bun
/**
 * prompt-blocker installer.
 *
 * Safely adds the plugin entry to an OpenCode configuration file. Run from
 * the skill directory:
 *
 *   bun scripts/install.ts [--global | --project <dir>] [--package <spec>]
 *                          [--mode <mode>] [--dry-run]
 *
 * Why a script instead of instructions to edit the file by hand: freehand
 * edits into strict `opencode.json` files can leave trailing commas or break
 * unrelated keys, which makes OpenCode fail to load its configuration at all.
 * This script:
 *
 *   - edits the existing file with a minimal textual splice: comments,
 *     formatting, and unrelated keys are preserved byte-for-byte;
 *   - never introduces a trailing comma (the result stays valid strict JSON
 *     even for `.json` files);
 *   - is idempotent (it detects an existing prompt-blocker entry);
 *   - validates that the edited file still parses BEFORE writing it;
 *   - keeps a backup next to the original.
 *
 * Dependency-free; runs under Bun (or any runtime that runs TypeScript).
 */

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import { resolve } from "node:path"

export const DEFAULT_PACKAGE = "github:psygreg/prompt-blocker"

// ---------------------------------------------------------------------------
// JSONC-aware scanner
// ---------------------------------------------------------------------------

interface Token {
  /** "string" tokens carry the raw quoted literal; "char" a single character. */
  type: "string" | "char"
  raw: string
  /** Index of the token's first character in the source text. */
  index: number
}

/**
 * Significant tokens of a JSON/JSONC document: whitespace and comments are
 * dropped, string literals are kept verbatim (escape-aware), everything else
 * is emitted character by character.
 */
export function scan(text: string): Token[] {
  const clean = text.startsWith("\uFEFF") ? text.slice(1) : text
  const offset = text.length - clean.length
  const tokens: Token[] = []
  let i = 0
  let inString = false
  let escape = false
  let stringStart = 0
  let comment: "none" | "line" | "block" = "none"
  while (i < clean.length) {
    const ch = clean[i]
    const next = clean[i + 1]
    if (comment === "line") {
      if (ch === "\n") comment = "none"
      i++
      continue
    }
    if (comment === "block") {
      if (ch === "*" && next === "/") {
        comment = "none"
        i += 2
        continue
      }
      i++
      continue
    }
    if (inString) {
      if (escape) escape = false
      else if (ch === "\\") escape = true
      else if (ch === '"') {
        inString = false
        tokens.push({ type: "string", raw: clean.slice(stringStart, i + 1), index: stringStart + offset })
      }
      i++
      continue
    }
    if (ch === '"') {
      inString = true
      stringStart = i
      i++
      continue
    }
    if (ch === "/" && next === "/") {
      comment = "line"
      i += 2
      continue
    }
    if (ch === "/" && next === "*") {
      comment = "block"
      i += 2
      continue
    }
    if (/\s/.test(ch)) {
      i++
      continue
    }
    tokens.push({ type: "char", raw: ch, index: i + offset })
    i++
  }
  return tokens
}

/**
 * Convert JSONC to strict JSON text: comments dropped, trailing commas
 * removed. String literals are untouched. Throws on nothing itself; the
 * result is meant for JSON.parse.
 */
export function toJson(text: string): string {
  const tokens = scan(text)
  let out = ""
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]
    if (token.type === "char" && token.raw === ",") {
      const next = tokens[i + 1]
      if (next && next.type === "char" && (next.raw === "]" || next.raw === "}")) continue
    }
    out += token.raw
  }
  return out
}

/** Parse a JSON or JSONC config. Throws on invalid documents. */
export function parseConfig(text: string): unknown {
  return JSON.parse(toJson(text))
}

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

interface TopLevelKey {
  keyIndex: number
  colonIndex: number
}

/** Find `"<key>":` among the members of the root object. */
function findTopLevelKey(tokens: Token[], key: string): TopLevelKey | undefined {
  let depth = 0
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]
    if (token.type === "char") {
      if (token.raw === "{" || token.raw === "[") depth++
      else if (token.raw === "}" || token.raw === "]") depth--
      continue
    }
    if (token.raw === `"${key}"` && depth === 1) {
      const colon = tokens[i + 1]
      if (colon && colon.type === "char" && colon.raw === ":") {
        return { keyIndex: i, colonIndex: i + 1 }
      }
    }
  }
  return undefined
}

interface ArrayRange {
  keyIndex: number
  openIndex: number
  closeIndex: number
}

/** Find the array value of a root-level key. */
function findTopLevelArray(tokens: Token[], key: string): ArrayRange | undefined {
  const found = findTopLevelKey(tokens, key)
  if (!found) return undefined
  const open = tokens[found.colonIndex + 1]
  if (!open || open.type !== "char" || open.raw !== "[") return undefined
  let depth = 0
  for (let i = found.colonIndex + 1; i < tokens.length; i++) {
    const token = tokens[i]
    if (token.type !== "char") continue
    if (token.raw === "{" || token.raw === "[") depth++
    else if (token.raw === "}" || token.raw === "]") {
      depth--
      if (token.raw === "]" && depth === 0) {
        return { keyIndex: found.keyIndex, openIndex: found.colonIndex + 1, closeIndex: i }
      }
    }
  }
  return undefined
}

interface RootRange {
  /** Token indices: first and last token of the last root member, if any. */
  lastMemberEnd: number | undefined
}

/** Locate the root object and its final member. */
function rootObjectRange(tokens: Token[]): RootRange | undefined {
  const open = tokens[0]
  if (!open || open.type !== "char" || open.raw !== "{") return undefined
  let depth = 1
  let lastMemberEnd: number | undefined
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i]
    if (token.type !== "char") continue
    if (token.raw === "{" || token.raw === "[") depth++
    else if (token.raw === "}" || token.raw === "]") {
      depth--
      if (depth === 0 && token.raw === "}") return { lastMemberEnd }
    }
    if (depth === 1 && token.raw !== ":") lastMemberEnd = i
  }
  return undefined
}

// ---------------------------------------------------------------------------
// Insertion
// ---------------------------------------------------------------------------

export type InsertStatus = "inserted" | "already-present" | "created-file" | "needs-manual"

export interface InsertResult {
  status: InsertStatus
  /** New file text for "inserted". */
  text?: string
  detail: string
}

/** Indentation (spaces or tabs) at the start of the line containing `index`. */
function lineIndentAt(text: string, index: number): string {
  const lineStart = text.lastIndexOf("\n", Math.max(0, index - 1)) + 1
  const before = text.slice(lineStart, index)
  const match = /^[ \t]*/.exec(before)
  return match ? match[0] : ""
}

function indentUnit(indent: string): string {
  return indent.includes("\t") ? "\t" : "  "
}

export function buildEntry(pkg: string, mode?: string): string {
  const options = mode ? `, "options": { "mode": "${mode}" }` : ""
  return `{ "package": "${pkg}"${options} }`
}

/** True when a parsed plugins array already references prompt-blocker. */
export function hasPromptBlocker(value: unknown): boolean {
  if (!Array.isArray(value)) return false
  return value.some((entry) => {
    if (typeof entry === "string") return entry.includes("prompt-blocker")
    if (entry && typeof entry === "object") {
      const pkg = (entry as { package?: unknown }).package
      return typeof pkg === "string" && pkg.includes("prompt-blocker")
    }
    return false
  })
}

/**
 * Add a prompt-blocker entry to config text with a minimal splice.
 * The input must be parseable JSON/JSONC; unparseable or surprising files
 * are refused rather than guessed at.
 */
export function insertPlugin(text: string, pkg: string, mode?: string): InsertResult {
  let parsed: unknown
  try {
    parsed = parseConfig(text)
  } catch (error) {
    return {
      status: "needs-manual",
      detail: `file does not parse as JSON/JSONC (${(error as Error).message}); refusing to touch it`,
    }
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { status: "needs-manual", detail: "top-level config value is not an object" }
  }

  const plugins = (parsed as Record<string, unknown>).plugins
  if (plugins !== undefined) {
    if (hasPromptBlocker(plugins)) {
      return { status: "already-present", detail: "a prompt-blocker plugin entry already exists" }
    }
    if (!Array.isArray(plugins)) {
      return { status: "needs-manual", detail: `"plugins" is not an array; edit the file manually` }
    }
  }

  const tokens = scan(text)
  const entry = buildEntry(pkg, mode)

  // Case 1: an existing plugins array — splice the entry into it.
  if (plugins !== undefined) {
    const array = findTopLevelArray(tokens, "plugins")
    if (!array) {
      return { status: "needs-manual", detail: `could not locate the "plugins" array in the text; edit manually` }
    }
    const keyIndent = lineIndentAt(text, tokens[array.keyIndex].index)
    const unit = indentUnit(keyIndent || "  ")
    const entryIndent = keyIndent + unit
    const body = tokens.slice(array.openIndex + 1, array.closeIndex)

    if (body.length === 0) {
      // "[]" — put the entry on its own line inside the brackets.
      const at = tokens[array.openIndex].index + 1
      const insertion = `\n${entryIndent}${entry}\n${keyIndent}`
      return { status: "inserted", text: text.slice(0, at) + insertion + text.slice(at), detail: "added the plugin to an empty plugins array" }
    }

    const last = body[body.length - 1]
    if (last.type === "char" && last.raw === ",") {
      // The array already ends with a trailing comma (JSONC style). Insert
      // just before the closing bracket — after any comments or whitespace
      // that follow the comma — so those stay attached to the entry they
      // documented, and the new entry itself carries no trailing comma.
      let at = tokens[array.closeIndex].index
      while (at > 0 && (text[at - 1] === " " || text[at - 1] === "\t")) at--
      const insertion = `${entryIndent}${entry}\n${keyIndent}`
      return { status: "inserted", text: text.slice(0, at) + insertion + text.slice(at), detail: "appended the plugin to the plugins array" }
    }
    const at = last.index + last.raw.length
    const insertion = `,\n${entryIndent}${entry}`
    return { status: "inserted", text: text.slice(0, at) + insertion + text.slice(at), detail: "appended the plugin to the plugins array" }
  }

  // Case 2: no plugins key — add one as the last member of the root object.
  const root = rootObjectRange(tokens)
  if (!root) {
    return { status: "needs-manual", detail: "could not locate the top-level object" }
  }
  const rootIndent = lineIndentAt(text, tokens[0].index)
  const unit = indentUnit(rootIndent || "  ")
  const keyIndent = rootIndent + unit
  const entryIndent = keyIndent + unit
  const pluginsBlock = `"plugins": [\n${entryIndent}${entry}\n${keyIndent}]`

  if (root.lastMemberEnd === undefined) {
    // Empty root object "{ }": add the member on its own line.
    const at = tokens[0].index + 1
    const insertion = `\n${keyIndent}${pluginsBlock}\n`
    return { status: "inserted", text: text.slice(0, at) + insertion + text.slice(at), detail: "added a plugins array" }
  }
  const lastToken = tokens[root.lastMemberEnd]
  const at = lastToken.index + lastToken.raw.length
  const insertion = `,\n${keyIndent}${pluginsBlock}\n`
  return { status: "inserted", text: text.slice(0, at) + insertion + text.slice(at), detail: "added a plugins array" }
}

/** Render a brand-new minimal config document. */
export function createConfig(pkg: string, mode?: string): string {
  const entry = buildEntry(pkg, mode)
  return [
    `{`,
    `  "$schema": "https://opencode.ai/config.json",`,
    `  "plugins": [`,
    `    ${entry}`,
    `  ]`,
    `}`,
    ``,
  ].join("\n")
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

interface Args {
  scope: "global" | "project"
  projectDir?: string
  pkg: string
  mode?: string
  dryRun: boolean
}

const USAGE = `prompt-blocker installer

  bun scripts/install.ts [--global | --project <dir>] [--package <spec>]
                         [--mode audit|standard|strict|permissive] [--dry-run]

  --global     edit the user-level config (default): ~/.config/opencode/opencode.json(c)
  --project D  edit one project's config: <D>/.opencode/opencode.json(c) or <D>/opencode.json(c)
  --package S  plugin spec to install (default: ${DEFAULT_PACKAGE})
  --mode M     also set the plugin's mode option
  --dry-run    show what would change without writing anything

The script only adds the plugins entry: comments, formatting, and unrelated
keys are preserved, the result is validated before it is written, a backup is
kept, and re-running it is safe (it detects existing prompt-blocker entries).`

function parseArgs(argv: string[]): Args {
  const args: Args = { scope: "global", pkg: DEFAULT_PACKAGE, dryRun: false }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    switch (arg) {
      case "--global":
        args.scope = "global"
        break
      case "--project": {
        args.scope = "project"
        args.projectDir = argv[++i]
        if (!args.projectDir) throw new Error("--project requires a directory")
        break
      }
      case "--package": {
        args.pkg = argv[++i]
        if (!args.pkg) throw new Error("--package requires a value")
        break
      }
      case "--mode": {
        const mode = argv[++i]
        if (!mode || !/^(audit|standard|strict|permissive)$/.test(mode)) {
          throw new Error("--mode must be one of audit, standard, strict, permissive")
        }
        args.mode = mode
        break
      }
      case "--dry-run":
        args.dryRun = true
        break
      case "--help":
      case "-h":
        console.log(USAGE)
        process.exit(0)
        break
      default:
        throw new Error(`unknown argument: ${arg}`)
    }
  }
  return args
}

function candidatePaths(args: Args): string[] {
  if (args.scope === "project") {
    const dir = resolve(args.projectDir ?? ".")
    return [`${dir}/.opencode/opencode.jsonc`, `${dir}/.opencode/opencode.json`, `${dir}/opencode.jsonc`, `${dir}/opencode.json`]
  }
  const config = `${homedir()}/.config/opencode`
  return [`${config}/opencode.jsonc`, `${config}/opencode.json`]
}

function nextSteps(): string {
  return [
    "next steps:",
    "  1. restart the background service: opencode service restart",
    "  2. verify: the /prompt-blocker command exists and a document-reviewer subagent is available",
  ].join("\n")
}

export async function run(argv: string[]): Promise<number> {
  const args = parseArgs(argv)
  const candidates = candidatePaths(args)

  // Prefer an existing file that already declares plugins; else any existing
  // file; else create the first candidate path.
  let firstExisting: string | undefined
  let withPlugins: string | undefined
  for (const path of candidates) {
    if (!existsSync(path)) continue
    firstExisting = firstExisting ?? path
    try {
      const parsed = parseConfig(readFileSync(path, "utf8")) as Record<string, unknown>
      if (parsed && typeof parsed === "object" && "plugins" in parsed) {
        withPlugins = path
        break
      }
    } catch {
      // Unparseable existing file: leave it alone.
    }
  }
  const file = withPlugins ?? firstExisting ?? candidates[0]

  if (!existsSync(file)) {
    const content = createConfig(args.pkg, args.mode)
    if (args.dryRun) {
      console.log(`[dry-run] would create ${file} with:`)
      console.log(content)
      return 0
    }
    mkdirSync(file.slice(0, file.lastIndexOf("/")), { recursive: true })
    writeFileSync(file, content, "utf8")
    console.log(`created ${file} with the prompt-blocker plugin`)
    console.log(nextSteps())
    return 0
  }

  const original = readFileSync(file, "utf8")
  const result = insertPlugin(original, args.pkg, args.mode)

  if (result.status === "already-present") {
    console.log(`prompt-blocker is already configured in ${file} — nothing to do.`)
    return 0
  }
  if (result.status === "needs-manual" || result.text === undefined) {
    console.error(`refused to edit ${file}: ${result.detail}`)
    console.error("Add this entry to the plugins array by hand, then validate the file parses before saving:")
    console.error(`  ${buildEntry(args.pkg, args.mode)}`)
    return 2
  }

  // Validate BEFORE writing. Strict JSON for .json files; tolerant for .jsonc.
  const newText = result.text
  try {
    if (file.endsWith(".json")) JSON.parse(newText)
    else parseConfig(newText)
  } catch (error) {
    console.error(`edited config failed validation (${(error as Error).message}); nothing was written.`)
    return 1
  }
  const check = parseConfig(newText) as Record<string, unknown>
  if (!Array.isArray(check.plugins) || !hasPromptBlocker(check.plugins)) {
    console.error("edited config does not contain a prompt-blocker plugins entry; nothing was written.")
    return 1
  }

  if (args.dryRun) {
    console.log(`[dry-run] would edit ${file}: ${result.detail}`)
    console.log(`  + ${buildEntry(args.pkg, args.mode)}`)
    return 0
  }

  const backup = `${file}.prompt-blocker.bak`
  copyFileSync(file, backup)
  writeFileSync(file, newText, "utf8")
  console.log(`${result.detail} in ${file}`)
  console.log(`backup written to ${backup}`)
  console.log(nextSteps())
  return 0
}

if (import.meta.main) {
  try {
    process.exit(await run(process.argv.slice(2)))
  } catch (error) {
    console.error((error as Error).message)
    console.error(USAGE)
    process.exit(1)
  }
}
