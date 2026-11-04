import { describe, expect, test } from "bun:test"
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describeSpill, spilledPluginFiles, spillEvidence } from "./layout.js"

describe("spilledPluginFiles", () => {
  test("matches prompt-blocker's own runtime modules", () => {
    expect(spilledPluginFiles(["apply.ts", "detect.ts", "policy.ts", "surface.ts", "surface.test.ts"])).toEqual([
      "apply.ts",
      "detect.ts",
      "policy.ts",
      "surface.test.ts",
      "surface.ts",
    ])
  })

  test("adds index.ts only alongside distinctive modules", () => {
    expect(spilledPluginFiles(["index.ts"])).toEqual([])
    expect(spilledPluginFiles(["index.ts", "index.js", "SKILL.md", "README.md"])).toEqual([])
    expect(spilledPluginFiles(["index.ts", "detect.ts"])).toEqual(["detect.ts", "index.ts"])
  })

  test("ignores unrelated files and near-name collisions", () => {
    expect(spilledPluginFiles(["my-apply.ts", "apply.ts.bak", "foo.ts", "README.md", "bun.lock"])).toEqual([])
  })

  test("matches .js variants of the runtime modules", () => {
    expect(spilledPluginFiles(["apply.js"])).toEqual(["apply.js"])
  })

  test("deduplicates and sorts the report", () => {
    expect(spilledPluginFiles(["detect.ts", "apply.ts", "detect.ts"])).toEqual(["apply.ts", "detect.ts"])
  })
})

describe("spillEvidence", () => {
  test("reports directories that hold spilled module files", () => {
    const root = mkdtempSync(join(tmpdir(), "pb-spill-evidence-"))
    try {
      const plugins = join(root, "plugins")
      mkdirSync(plugins, { recursive: true })
      for (const file of ["index.ts", "apply.ts", "detect.ts"]) writeFileSync(join(plugins, file), "")
      const evidence = spillEvidence([join(root, "missing"), plugins])
      expect(evidence).toEqual([{ dir: plugins, files: ["apply.ts", "detect.ts", "index.ts"] }])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("skips healthy package directories and missing candidates", () => {
    const root = mkdtempSync(join(tmpdir(), "pb-spill-clean-"))
    try {
      const pkg = join(root, "prompt-blocker")
      mkdirSync(join(pkg, "src"), { recursive: true })
      writeFileSync(join(pkg, "package.json"), "{}")
      writeFileSync(join(pkg, "src", "index.ts"), "")
      expect(spillEvidence([join(root, "nope"), pkg])).toEqual([])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("does not double-report the same directory", () => {
    const root = mkdtempSync(join(tmpdir(), "pb-spill-dup-"))
    try {
      const plugins = join(root, "plugins")
      mkdirSync(plugins, { recursive: true })
      writeFileSync(join(plugins, "policy.ts"), "")
      expect(spillEvidence([plugins, plugins, join(plugins, "", "")])).toEqual([
        { dir: plugins, files: ["policy.ts"] },
      ])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

describe("describeSpill", () => {
  test("formats a directory with its spilled files", () => {
    expect(describeSpill("/tmp/plugins", ["apply.ts", "detect.ts"])).toBe("/tmp/plugins (apply.ts, detect.ts)")
  })
})
