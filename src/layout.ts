/**
 * Spilled-install evidence.
 *
 * OpenCode loads every file placed directly inside a plugins directory
 * (`.opencode/plugins/`, `~/.config/opencode/plugins/`) as its own separate
 * plugin. A manual or agent-driven install that copies prompt-blocker's
 * source files flat into such a directory therefore breaks the plugin into
 * several broken plugins and strands its bundled skill document — the
 * "files spilled out of a proper directory" failure. This module recognizes
 * that layout so the plugin can name the leftover files in its degraded
 * notice and its `/prompt-blocker` status instead of guessing.
 *
 * Pure module: no OpenCode imports, so the matcher is unit-testable.
 */

import { readdirSync } from "node:fs"

/**
 * Basenames (without extension) of prompt-blocker's own runtime modules.
 * Their presence as loose `.ts`/`.js` files in a plugins directory is strong
 * evidence of a spilled install. `index` is excluded: a single `index.ts` is
 * too generic to stand alone as evidence. Test files count too — they are
 * equally incompatible with the plugins directory.
 */
const OWN_MODULES = new Set(["apply", "detect", "policy", "surface", "images", "surface.test", "images.test"])

/** Which of `files` look like prompt-blocker's runtime modules. */
export function spilledPluginFiles(files: string[]): string[] {
  const distinctive: string[] = []
  for (const file of files) {
    const base = file.startsWith("index.") || file.startsWith("SKILL")
      ? ""
      : file.slice(0, file.lastIndexOf("."))
    if (base !== "" && OWN_MODULES.has(base)) distinctive.push(file)
  }
  // `index.ts` / `index.js` only ride along when prompt-blocker's distinctive
  // modules are part of the same spill; alone the name is too common to report.
  const hits = [...distinctive]
  if (distinctive.length > 0 && (files.includes("index.ts") || files.includes("index.js")))
    hits.push(files.includes("index.ts") ? "index.ts" : "index.js")
  return [...new Set(hits)].sort()
}

/**
 * Best-effort scan of candidate directories for spilled files. Missing or
 * unreadable directories are skipped; this must never throw or block startup.
 */
export function spillEvidence(dirs: string[]): Array<{ dir: string; files: string[] }> {
  const seen = new Set<string>()
  const evidence: Array<{ dir: string; files: string[] }> = []
  for (const dir of dirs) {
    if (!dir || seen.has(dir)) continue
    seen.add(dir)
    try {
      const files = spilledPluginFiles(readdirSync(dir))
      if (files.length > 0) evidence.push({ dir, files })
    } catch {
      // Unreadable or missing candidate: not evidence.
    }
  }
  return evidence
}

/** Render one evidence record for the degraded notice / status output. */
export function describeSpill(dir: string, files: string[]): string {
  return `${dir} (${files.join(", ")})`
}
