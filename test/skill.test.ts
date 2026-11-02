import { describe, expect, test } from "bun:test"
import { parse } from "yaml"
import { SKILL_DESCRIPTION } from "../src/index.js"

const SKILL_FILE = new URL("../skill/SKILL.md", import.meta.url)

function frontmatter(text: string): string {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text)
  if (!match) throw new Error("SKILL.md has no frontmatter block")
  return match[1]
}

describe("skill/SKILL.md", () => {
  test("frontmatter parses as strict YAML", async () => {
    const text = await Bun.file(SKILL_FILE).text()
    const data = parse(frontmatter(text))
    expect(data).toBeObject()
  })

  test("frontmatter has the expected shape", async () => {
    const text = await Bun.file(SKILL_FILE).text()
    const data = parse(frontmatter(text)) as Record<string, string>
    expect(data.name).toBe("Prompt Blocker")
    expect(typeof data.description).toBe("string")
    expect(data.description.length).toBeGreaterThan(50)
    // Values must be plain single-line scalars: a colon+space inside an
    // unquoted value is a nested-mapping parse error in strict YAML parsers
    // (the skill installer rejects the whole file for it).
    for (const [key, value] of Object.entries(data)) {
      expect(value).not.toMatch(/:\s/)
      expect(value).not.toContain("\n")
      expect(key).toMatch(/^[a-zA-Z][\w-]*$/)
    }
  })

  test("registered description matches the SKILL.md frontmatter", async () => {
    const text = await Bun.file(SKILL_FILE).text()
    const data = parse(frontmatter(text)) as Record<string, string>
    expect(SKILL_DESCRIPTION).toBe(data.description)
  })
})
