# Agent Guidelines (AGENTS.md)

This document outlines the mandatory rules and workflow for all AI agents working within this repository. Adherence to these guidelines is required for task completion and code quality.

## 📜 Code Development Standards
Agents must adhere to standard best practices for the languages used:
- **TypeScript:** Follow idiomatic TypeScript under the repo's strict [tsconfig.json](../tsconfig.json) (strict mode, ESNext target/module, bundler resolution, `verbatimModuleSyntax`). Ensure functional correctness and readability. Everything must typecheck clean with `bun run check` (`tsc --noEmit`) and run under [Bun](https://bun.sh), which is both the runtime and the test runner. Relative imports carry the `.js` extension (`./detect.js`), matching the existing code; Node built-ins are imported through the `node:` prefix.
- **Dependencies:** The plugin's only runtime dependency is the `@opencode/plugin` peer (`>= 2`). Do not add new dependencies: prompt-blocker is a security tool, and every added package widens the supply chain the plugin must itself be trusted against. [skill/scripts/install.ts](../skill/scripts/install.ts) is deliberately dependency-free — keep it that way.
- **Pure-module rule:** Core logic lives in pure modules — [detect.ts](../src/detect.ts), [apply.ts](../src/apply.ts), [policy.ts](../src/policy.ts), [layout.ts](../src/layout.ts), [surface.ts](../src/surface.ts), [images.ts](../src/images.ts), and [confine.ts](../src/confine.ts) with filesystem access injected as dependencies. Only [src/index.ts](../src/index.ts) may import `@opencode/plugin`; keep it that way so the core stays unit-testable without OpenCode.
- **Fail-closed discipline:** Enforcement fails closed: undecodable or unrecognized input is refused, never guessed at, and data crossing a result boundary (e.g. a scan report returned inside tool-result metadata) is shape-validated and treated as critical when malformed. Model-facing banners describe findings (categories, counts, line numbers) and never echo attacker payload text into model context; verbatim excerpts belong only in user-facing confirmation prompts. Hooks that merely observe (logging, granting, report rewriting) catch their own errors; hooks that enforce throw deliberately.

## 🧪 Testing Requirement
**All changes must be accompanied by temporary test harnesses.**
1.  Before considering a task complete, the change must pass associated tests.
2.  These temporary test harnesses can be discarded once all tests have successfully passed and verified the task completion and absence of regressions.
3.  Do not submit code without demonstrable proof of correctness via tests.

## 🚫 Workflow Policy
**Agents must never commit or push code themselves.**
- All changes must remain **uncommitted** in the working directory.
- Agents should stage changes (e.g., `git add .`) but *not* commit them.
- The agent's role is to prepare the changes; human review is required for committing and pushing.

## 🚫 Repository Information Upkeep
**The [ARCHITECTURE.md](ARCHITECTURE.md) file must always be kept up-to-date.**
- Any sufficiently relevant changes must be reflected in the file.

## 🗺️ Documentation
For a detailed map of modules, functions, and application structure, please refer to [ARCHITECTURE.md](ARCHITECTURE.md).
