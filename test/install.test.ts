import { describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import {
  buildEntry,
  createConfig,
  hasPromptBlocker,
  insertPlugin,
  parseConfig,
  scan,
  toJson,
} from "../skill/scripts/install.js"

/** The shape that broke in the wild: strict opencode.json, existing object-form plugin. */
const USER_CONFIG = `{
  "mcp": {
    "servers": {
      "ai-memory": {
        "type": "remote",
        "url": "http://127.0.0.1:49374/mcp",
        "oauth": false
      }
    }
  },
  "plugins": [
    {
      "package": "./plugins/reflex",
      "options": {
        "provider": "custom",
        "baseURL": "http://127.0.0.1:1123/v1",
        "model": "liquid-d1"
      }
    }
  ]
}
`

describe("scanner", () => {
  test("strips line and block comments", () => {
    const text = `{
  // a comment
  "a": 1, /* block
comment */ "b": 2
}`
    expect(JSON.parse(toJson(text))).toEqual({ a: 1, b: 2 })
  })

  test("removes trailing commas, keeps content commas", () => {
    const text = `{"a": [1, 2, 3,], "b": {"c": 1,},}`
    expect(JSON.parse(toJson(text))).toEqual({ a: [1, 2, 3], b: { c: 1 } })
  })

  test("does not touch comment or slash characters inside strings", () => {
    const text = `{"url": "http://x//y", "note": "not // a comment"}`
    expect(JSON.parse(toJson(text))).toEqual({ url: "http://x//y", note: "not // a comment" })
  })

  test("token indexes point into the original text", () => {
    const text = `{\n  "key": "value"\n}`
    const tokens = scan(text)
    const key = tokens.find((t) => t.type === "string" && t.raw === '"key"')
    expect(key).toBeDefined()
    expect(key?.index).toBe(text.indexOf('"key"'))
    const value = tokens.find((t) => t.type === "string" && t.raw === '"value"')
    expect(value?.index).toBe(text.indexOf('"value"'))
  })

  test("parseConfig accepts JSONC and rejects garbage", () => {
    expect(parseConfig(`{"a": 1, // c\n}`)).toEqual({ a: 1 })
    expect(() => parseConfig(`{"a":`)).toThrow()
  })
})

describe("insertPlugin", () => {
  test("REGRESSION: appends to a strict .json config without trailing commas", () => {
    const result = insertPlugin(USER_CONFIG, "github:psygreg/prompt-blocker")
    expect(result.status).toBe("inserted")
    expect(result.text).toBeDefined()
    // Must survive STRICT JSON parsing — the original incident was a trailing
    // comma before the closing bracket, which killed OpenCode at config load.
    const parsed = JSON.parse(result.text!) as { plugins: unknown[]; mcp: unknown }
    expect(parsed.plugins).toHaveLength(2)
    expect(parsed.plugins[1]).toEqual({ package: "github:psygreg/prompt-blocker" })
    // The existing entry and unrelated keys are untouched.
    expect(parsed.plugins[0]).toEqual({
      package: "./plugins/reflex",
      options: { provider: "custom", baseURL: "http://127.0.0.1:1123/v1", model: "liquid-d1" },
    })
    expect(parsed.mcp).toBeDefined()
    // And the edit is a minimal splice: everything before the plugins array is byte-identical.
    const originalUpTo = USER_CONFIG.slice(0, USER_CONFIG.indexOf('"plugins"'))
    expect(result.text!.startsWith(originalUpTo)).toBe(true)
  })

  test("preserves JSONC comments and existing trailing commas", () => {
    const config = `{
  // my config
  "model": "opencode/glm",
  "plugins": [
    "agent-reflex", // trailing comma style
  ]
}`
    const result = insertPlugin(config, "github:psygreg/prompt-blocker")
    expect(result.status).toBe("inserted")
    expect(result.text).toContain("// my config")
    expect(result.text).toContain('"agent-reflex", // trailing comma style')
    const parsed = parseConfig(result.text!) as { plugins: unknown[]; model: string }
    expect(parsed.model).toBe("opencode/glm")
    expect(parsed.plugins).toEqual(["agent-reflex", { package: "github:psygreg/prompt-blocker" }])
    // The new entry must not end with a trailing comma either.
    expect(result.text).not.toMatch(/prompt-blocker" \},\s*\]/)
  })

  test("appends after string-form entries", () => {
    const config = `{"plugins": ["agent-reflex"]}`
    const result = insertPlugin(config, "github:psygreg/prompt-blocker")
    expect(result.status).toBe("inserted")
    expect(JSON.parse(result.text!).plugins).toEqual(["agent-reflex", { package: "github:psygreg/prompt-blocker" }])
  })

  test("fills an empty plugins array", () => {
    const config = `{\n  "plugins": []\n}\n`
    const result = insertPlugin(config, "github:psygreg/prompt-blocker")
    expect(result.status).toBe("inserted")
    expect(JSON.parse(result.text!).plugins).toEqual([{ package: "github:psygreg/prompt-blocker" }])
    expect(result.text).toContain("[\n    { \"package\"")
  })

  test("adds a plugins array when the key is missing", () => {
    const config = `{\n  "mcp": {\n    "servers": {}\n  }\n}\n`
    const result = insertPlugin(config, "github:psygreg/prompt-blocker")
    expect(result.status).toBe("inserted")
    const parsed = JSON.parse(result.text!) as { plugins: unknown[]; mcp: unknown }
    expect(parsed.mcp).toEqual({ servers: {} })
    expect(parsed.plugins).toEqual([{ package: "github:psygreg/prompt-blocker" }])
  })

  test("handles an empty root object", () => {
    const result = insertPlugin(`{\n}\n`, "github:psygreg/prompt-blocker")
    expect(result.status).toBe("inserted")
    expect(JSON.parse(result.text!).plugins).toEqual([{ package: "github:psygreg/prompt-blocker" }])
  })

  test("respects a custom package spec and mode option", () => {
    const result = insertPlugin(USER_CONFIG, "prompt-blocker", "audit")
    const parsed = JSON.parse(result.text!) as { plugins: { package: string; options?: { mode: string } }[] }
    expect(parsed.plugins[1]).toEqual({ package: "prompt-blocker", options: { mode: "audit" } })
  })

  test("is idempotent", () => {
    const once = insertPlugin(USER_CONFIG, "github:psygreg/prompt-blocker")
    const twice = insertPlugin(once.text!, "github:psygreg/prompt-blocker")
    expect(twice.status).toBe("already-present")
    expect(twice.text).toBeUndefined()
  })

  test("detects existing entries in both string and object form", () => {
    expect(insertPlugin(`{"plugins": ["github:psygreg/prompt-blocker"]}`, "x").status).toBe("already-present")
    expect(insertPlugin(`{"plugins": [{"package": "prompt-blocker"}]}`, "x").status).toBe("already-present")
    expect(insertPlugin(`{"plugins": [{"package": "./plugins/prompt-blocker"}]}`, "x").status).toBe("already-present")
  })

  test("refuses unparseable or surprising files", () => {
    expect(insertPlugin(`{"plugins": [`, "x").status).toBe("needs-manual")
    expect(insertPlugin(`not json at all`, "x").status).toBe("needs-manual")
    expect(insertPlugin(`{"plugins": "nope"}`, "x").status).toBe("needs-manual")
    expect(insertPlugin(`[1, 2]`, "x").status).toBe("needs-manual")
  })

  test("createConfig renders a valid minimal document", () => {
    const created = createConfig("github:psygreg/prompt-blocker", "audit")
    const parsed = JSON.parse(created) as { $schema: string; plugins: unknown[] }
    expect(parsed.$schema).toBe("https://opencode.ai/config.json")
    expect(parsed.plugins).toEqual([{ package: "github:psygreg/prompt-blocker", options: { mode: "audit" } }])
  })
})

describe("hasPromptBlocker / buildEntry", () => {
  test("matches strings and objects, ignores others", () => {
    expect(hasPromptBlocker(["prompt-blocker"])).toBe(true)
    expect(hasPromptBlocker([{ package: "github:psygreg/prompt-blocker" }])).toBe(true)
    expect(hasPromptBlocker([{ package: "agent-reflex" }])).toBe(false)
    expect(hasPromptBlocker([])).toBe(false)
    expect(hasPromptBlocker(undefined)).toBe(false)
    expect(hasPromptBlocker("prompt-blocker")).toBe(false)
  })

  test("buildEntry with and without mode", () => {
    expect(buildEntry("p")).toBe(`{ "package": "p" }`)
    expect(buildEntry("p", "audit")).toBe(`{ "package": "p", "options": { "mode": "audit" } }`)
  })
})

describe("install CLI end-to-end", () => {
  test("installs into a temporary global config, backs up, and is idempotent", async () => {
    const home = `/tmp/opencode/install-test-${Date.now()}`
    const configDir = `${home}/.config/opencode`
    mkdirSync(configDir, { recursive: true })
    writeFileSync(`${configDir}/opencode.json`, USER_CONFIG)

    const script = new URL("../skill/scripts/install.ts", import.meta.url).pathname
    const env = { ...process.env, HOME: home }

    const first = Bun.spawnSync(["bun", script, "--global"], { env, stdout: "pipe", stderr: "pipe" })
    expect(first.exitCode).toBe(0)
    expect(first.stdout.toString()).toContain("backup written to")

    const edited = readFileSync(`${configDir}/opencode.json`, "utf8")
    const parsed = JSON.parse(edited) as { plugins: unknown[] }
    expect(parsed.plugins).toHaveLength(2)
    expect(existsSync(`${configDir}/opencode.json.prompt-blocker.bak`)).toBe(true)
    expect(readFileSync(`${configDir}/opencode.json.prompt-blocker.bak`, "utf8")).toBe(USER_CONFIG)

    const second = Bun.spawnSync(["bun", script, "--global"], { env, stdout: "pipe", stderr: "pipe" })
    expect(second.exitCode).toBe(0)
    expect(second.stdout.toString()).toContain("already configured")
    expect(readFileSync(`${configDir}/opencode.json`, "utf8")).toBe(edited)
  })
})
