/**
 * prompt-blocker detection engine.
 *
 * Pure text analysis with no OpenCode imports so it can be unit-tested in
 * isolation. Two entry points:
 *
 *   scanText(text, opts)      -> ScanReport   (what was found, how severe)
 *   sanitizeText(text, report) -> { text, notes }   (strip concealed signals)
 *
 * Design rule: the report describes findings without echoing attacker
 * payloads. Excerpts are kept separate (`excerpts`) and are only surfaced to
 * the human user during confirmation prompts, never injected into model
 * context through banners.
 */

export type Verdict = "clean" | "suspicious" | "likely" | "critical"

export type CategoryId =
  | "tag-characters"
  | "bidi-override"
  | "hidden-unicode"
  | "encoded-invisible-entity"
  | "variation-selector"
  | "private-use"
  | "hidden-styling"
  | "hidden-comment-phrase"
  | "metadata-phrase"
  | "frontmatter-directive"
  | "encoded-payload"
  | "instruction-phrase"

export interface Detection {
  id: CategoryId
  /** Human-readable label used in banners and reports. */
  label: string
  /** Occurrence count. */
  count: number
  /** Contribution to the total score, after per-category caps. */
  weight: number
  /** Line numbers of the first few occurrences (1-based). */
  lines: number[]
  /** Short non-payload notes, e.g. "decoded hidden text contains instruction phrases". */
  details: string[]
  /** True when this category hides content from the reader in some way. */
  concealment: boolean
  /** Truncated attacker-controlled excerpts. For user-facing prompts only. */
  excerpts: string[]
}

export interface ScanReport {
  verdict: Verdict
  score: number
  detections: Detection[]
  /** A phrase class aimed at the agent was found in a concealed location. */
  concealedPhrase: boolean
  /** Hidden tag-character or encoded-payload text decoded to instruction phrases. */
  decodedPayload: boolean
  /** Bytes actually scanned (input may have been truncated). */
  scannedBytes: number
  truncated: boolean
}

export interface ScanOptions {
  /** Additional literal phrases to treat as instruction phrases. */
  extraPhrases?: string[]
  /** Override the byte cap. The default matches policy defaults. */
  maxBytes?: number
}

// ---------------------------------------------------------------------------
// Unicode signal tables
// ---------------------------------------------------------------------------

/** Zero-width / invisible format characters (code points). */
const ZERO_WIDTH = new Set<number>([
  0x200b, // zero width space
  0x200c, // zero width non-joiner
  0x200d, // zero width joiner
  0x2060, // word joiner
  0x2061, // function application
  0x2062, // invisible times
  0x2063, // invisible separator
  0x2064, // invisible plus
  0xfeff, // zero width no-break space (BOM)
  0x180e, // mongolian vowel separator
])

/** Bidirectional override controls (Trojan Source attacks). */
const BIDI = new Set<number>([0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069])

/** Soft hyphen: only a signal in numbers. */
const SOFT_HYPHEN = 0x00ad

/** Private use area (symbol fonts such as Wingdings). */
const PUA_RE = /[\uE000-\uF8FF]/g

/** Variation selectors, excluding VS15/VS16 which are common with emoji. */
const VARIATION_RE = /[\uFE00-\uFE0D]/g

// ---------------------------------------------------------------------------
// Phrase classes
// ---------------------------------------------------------------------------

interface PhraseClass {
  id: string
  weight: number
  containerOnly: boolean
  patterns: RegExp[]
}

function rx(source: string): RegExp {
  return new RegExp(source, "gi")
}

const PHRASE_CLASSES: PhraseClass[] = [
  {
    id: "override",
    weight: 22,
    containerOnly: false,
    patterns: [
      rx(
        "\\bignore\\s+(?:all\\s+|any\\s+|the\\s+|your\\s+)?(?:previous|prior|above|earlier|preceding|past)\\b[\\s\\S]{0,40}?\\b(?:instructions?|directions?|rules?|prompts?|context|messages?|system)\\b",
      ),
      rx("\\bdisregard\\b[\\s\\S]{0,40}?\\b(?:instructions?|directions?|rules?|prompts?|the\\s+above|previous|prior)\\b"),
      rx("\\bforget\\s+(?:all|everything|about)\\b[\\s\\S]{0,40}?\\b(?:instructions?|rules?|prompts?|previous|prior|above|context)\\b"),
      rx(
        "\\b(?:override|replace|supersede|bypass)\\b[\\s\\S]{0,30}?\\b(?:your|the|all|any)?\\s*(?:system\\s+)?(?:instructions?|rules?|prompts?|guardrails?|safety\\s+rules?|configuration)\\b",
      ),
      rx("\\b(?:new|updated|revised)\\s+(?:instructions?|rules?|directives?)\\s*[:\\-\u2014]"),
    ],
  },
  {
    id: "identity",
    weight: 14,
    containerOnly: false,
    patterns: [
      rx("\\byou\\s+are\\s+now\\b"),
      rx("\\bact\\s+as\\s+if\\s+(?:you|he|she|it|the)\\b"),
      rx("\\bpretend\\s+(?:to\\s+be|you\\s+are)\\b"),
      rx("\\bfrom\\s+now\\s+on\\b[\\s\\S]{0,30}?\\b(?:you\\s+(?:are|must|will|should)|ignore|disregard|always|never)\\b"),
      rx("\\b(?:enter|enable|activate|switch\\s+to)\\s+(?:developer|god|DAN|jailbreak)\\s+mode\\b"),
      rx("\\bjailbreak\\b"),
    ],
  },
  {
    id: "secrecy",
    weight: 22,
    containerOnly: false,
    patterns: [
      rx("\\b(?:do\\s+not|don'?t)\\s+tell\\s+(?:the\\s+)?user\\b"),
      rx("\\b(?:keep|hide)\\s+(?:this|it|that|these|them)\\s+(?:secret|hidden|confidential)\\b"),
      rx("\\bhide\\s+(?:this|it|that)\\s+from\\s+(?:the\\s+)?user\\b"),
      rx("\\bwithout\\s+(?:the\\s+)?user'?s?\\s+(?:knowledge|consent|approval)\\b"),
      rx("\\b(?:do\\s+not|don'?t)\\s+(?:inform|notify|alert|warn|mention|reveal)\\b[\\s\\S]{0,30}?\\b(?:user|human|operator|owner)\\b"),
    ],
  },
  {
    id: "exfiltration",
    weight: 28,
    containerOnly: false,
    patterns: [
      rx(
        "\\b(?:send|upload|post|transmit|exfiltrate|email|forward|transfer)\\b[\\s\\S]{0,60}?\\b(?:to|at|on|via)\\s+(?:https?://|this\\s+(?:url|endpoint|server|webhook|address)|an?\\s+external)\\b",
      ),
      rx(
        "\\b(?:send|upload|exfiltrate|leak|share)\\b[\\s\\S]{0,40}?\\b(?:files?|contents?|data|credentials?|tokens?|keys?|secrets?|passwords?|env(?:ironment)?\\s+variables?|conversation|history|transcript)\\b",
      ),
    ],
  },
  {
    id: "reveal",
    weight: 16,
    containerOnly: false,
    patterns: [
      rx(
        "\\b(?:repeat|print|output|display|show|reveal|recite|write\\s+out)\\b[\\s\\S]{0,40}?\\b(?:your|the|this|my)\\s*(?:initial|original|system|hidden|secret|true)?\\s*(?:prompt|instructions?|rules?|configuration)\\b",
      ),
      rx("\\b(?:repeat|output|recite)\\b[\\s\\S]{0,20}?\\beverything\\b[\\s\\S]{0,20}?\\b(?:above|before|that|prior)\\b"),
    ],
  },
  {
    id: "targeting",
    weight: 8,
    containerOnly: false,
    patterns: [
      rx("\\b(?:hey|hi|hello|dear|attention|note\\s+to)\\s+(?:the\\s+)?(?:AI|A\\.I\\.|agent|assistant|bot|model|LLM|GPT|Claude|Copilot)\\b"),
      rx(
        "\\b(?:AI|assistant|agent|LLM)\\s*[:\\-]\\s*(?:please|you\\s+(?:must|should|are|will)|ignore|read|do|don'?t|never|always|before|after|when)\\b",
      ),
      rx("\\b(?:system|developer)\\s+(?:prompt|message|role)\\s*[:\\-\u2014]"),
    ],
  },
  {
    id: "tool-invocation",
    weight: 22,
    // Only counted inside concealed containers: too FP-prone in visible code.
    containerOnly: true,
    patterns: [
      rx("\\b(?:call|invoke|run|execute|use)\\b[\\s\\S]{0,20}?\\b(?:the\\s+)?(?:tool|command|function|script|bash|shell|terminal)\\b"),
      rx("\\b(?:curl|wget|nc|netcat|ssh)\\s+"),
    ],
  },
]

// ---------------------------------------------------------------------------
// Hidden styling patterns
// ---------------------------------------------------------------------------

const HIDDEN_STYLING: { id: string; pattern: RegExp }[] = [
  { id: "tiny-font", pattern: /font-size\s*:\s*(?:0(?:\.\d+)?(?:px|em|rem|pt|%)?|[123]px|0\.0\d+(?:em|rem|pt)?|1pt|2pt)\b/gi },
  { id: "opacity-zero", pattern: /(?:^|["';\s{])opacity\s*:\s*0(?:\.0+)?\s*(?:!important)?\s*(?:["';}]|$)/gi },
  { id: "visibility-hidden", pattern: /visibility\s*:\s*hidden/gi },
  { id: "display-none", pattern: /display\s*:\s*none/gi },
  { id: "hidden-attribute", pattern: /<[a-z][^>]*\shidden(?:\s*[=>]|\s+[a-z-])/gi },
  { id: "offscreen-position", pattern: /(?:left|right|top|margin-left|margin-right|text-indent)\s*:\s*-(?:[1-9]\d{2,}|9999)(?:px|em|rem)/gi },
  { id: "absolute-offscreen", pattern: /position\s*:\s*(?:absolute|fixed)[^;}]{0,120}?(?:left|top)\s*:\s*-\d{3,}/gi },
  { id: "transparent-text", pattern: /color\s*:\s*transparent/gi },
  {
    id: "white-on-white",
    pattern: new RegExp(
      [
        /color\s*:\s*(?:white|#fff(?:fff)?|rgba?\(\s*255\s*,\s*255\s*,\s*255[^)]*\))/.source,
        /[^}]{0,200}?/.source,
        /background(?:-color)?\s*:\s*(?:white|#fff(?:fff)?|rgba?\(\s*255\s*,\s*255\s*,\s*255[^)]*\))/.source,
      ].join(""),
      "gi",
    ),
  },
  {
    id: "white-on-white-reversed",
    pattern: new RegExp(
      [
        /background(?:-color)?\s*:\s*(?:white|#fff(?:fff)?|rgba?\(\s*255\s*,\s*255\s*,\s*255[^)]*\))/.source,
        /[^}]{0,200}?/.source,
        /color\s*:\s*(?:white|#fff(?:fff)?|rgba?\(\s*255\s*,\s*255\s*,\s*255[^)]*\))/.source,
      ].join(""),
      "gi",
    ),
  },
]

// ---------------------------------------------------------------------------
// Containers (HTML comments, script/style bodies, attributes, frontmatter)
// ---------------------------------------------------------------------------

interface Container {
  kind: "comment" | "script" | "attribute" | "meta" | "frontmatter"
  body: string
  index: number
}

function extractContainers(text: string): Container[] {
  const containers: Container[] = []
  const commentRe = /<!--([\s\S]{0,10000}?)-->/g
  for (const m of text.matchAll(commentRe)) containers.push({ kind: "comment", body: m[1] ?? "", index: m.index ?? 0 })
  const scriptRe = /<(script|style)\b[^>]*>([\s\S]{0,20000}?)<\/\1\s*>/gi
  for (const m of text.matchAll(scriptRe)) containers.push({ kind: "script", body: m[2] ?? "", index: m.index ?? 0 })
  const attrRe =
    /(?:\balt|\btitle|\baria-label|\baria-description|\baria-placeholder|\bplaceholder|\bdata-[\w-]+)\s*=\s*(?:"([^"\n]{12,300})"|'([^'\n]{12,300})')/gi
  for (const m of text.matchAll(attrRe)) {
    const body = m[1] ?? m[2] ?? ""
    if (body) containers.push({ kind: "attribute", body, index: m.index ?? 0 })
  }
  const metaRe = /<meta\b[^>]*\bcontent\s*=\s*(?:"([^"\n]{12,300})"|'([^'\n]{12,300})')/gi
  for (const m of text.matchAll(metaRe)) {
    const body = m[1] ?? m[2] ?? ""
    if (body) containers.push({ kind: "meta", body, index: m.index ?? 0 })
  }
  const fm = /^---\r?\n([\s\S]{0,4000}?)\r?\n---(?:\r?\n|$)/.exec(text)
  if (fm) {
    const directiveKeys = /^\s*(?:system|prompt|instructions?|role|assistant|developer|directive)s?\s*:\s*(.+)$/gim
    for (const m of fm[1].matchAll(directiveKeys)) {
      containers.push({ kind: "frontmatter", body: m[1] ?? "", index: m.index ?? 0 })
    }
  }
  return containers
}

// ---------------------------------------------------------------------------
// Normalization (entity + percent decoding) for obfuscated phrase detection
// ---------------------------------------------------------------------------

const NAMED_ENTITIES: Record<string, string> = {
  nbsp: " ",
  amp: "&",
  quot: '"',
  lt: "<",
  gt: ">",
  apos: "'",
}

function decodeNumericEntity(hex: string | undefined, dec: string | undefined): string | undefined {
  const cp = hex ? parseInt(hex, 16) : dec ? parseInt(dec, 10) : NaN
  if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) return undefined
  try {
    return String.fromCodePoint(cp)
  } catch {
    return undefined
  }
}

/** One-pass, non-recursive decode of numeric/named entities and %XX sequences. */
export function normalizeForPhraseScan(text: string): string {
  let out = text.replace(/&#x([0-9a-fA-F]+);?|&#(\d+);?|&([a-zA-Z]{2,10});/g, (full, hex: string, dec: string, name: string) => {
    if (hex || dec) return decodeNumericEntity(hex, dec) ?? full
    return NAMED_ENTITIES[name.toLowerCase()] ?? full
  })
  if (out.includes("%")) {
    out = out.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
      try {
        return decodeURIComponent(run)
      } catch {
        return run
      }
    })
  }
  return out
}

// ---------------------------------------------------------------------------
// Line lookup
// ---------------------------------------------------------------------------

function lineOffsets(text: string): number[] {
  const offsets: number[] = []
  let idx = text.indexOf("\n")
  while (idx !== -1) {
    offsets.push(idx)
    idx = text.indexOf("\n", idx + 1)
  }
  return offsets
}

function lineOf(offsets: number[], index: number): number {
  let lo = 0
  let hi = offsets.length - 1
  let line = 1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    if (offsets[mid] < index) {
      line = mid + 2
      lo = mid + 1
    } else {
      hi = mid - 1
    }
  }
  return line
}

function firstLines(offsets: number[], indexes: number[], max = 5): number[] {
  const lines = indexes.slice(0, max).map((i) => lineOf(offsets, i))
  return [...new Set(lines)].slice(0, max)
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

function excerpt(text: string, index: number, radius = 40): string {
  const start = Math.max(0, index - radius)
  const end = Math.min(text.length, index + radius)
  let slice = text.slice(start, end).replace(/\s+/g, " ").trim()
  if (start > 0) slice = "\u2026" + slice
  if (end < text.length) slice = slice + "\u2026"
  return slice.length > 120 ? slice.slice(0, 120) + "\u2026" : slice
}

interface PhraseHit {
  classId: string
  index: number
}

/**
 * Scan for phrase classes.
 *
 * - "visible" runs every class not marked containerOnly against the text the
 *   reader actually sees.
 * - "container" runs every class, including the FP-prone tool-invocation
 *   class, because a comment/metadata field is already a concealed location.
 */
function scanPhrases(
  text: string,
  mode: "visible" | "container",
  extra: string[] | undefined,
): { hits: PhraseHit[]; classes: Map<string, number> } {
  const hits: PhraseHit[] = []
  const classes = new Map<string, number>()
  const classesToRun = extra && extra.length > 0 ? [...PHRASE_CLASSES, makeExtraClass(extra)] : PHRASE_CLASSES
  for (const cls of classesToRun) {
    if (mode === "visible" && cls.containerOnly) continue
    let count = 0
    for (const pattern of cls.patterns) {
      pattern.lastIndex = 0
      let m: RegExpExecArray | null
      while ((m = pattern.exec(text)) !== null) {
        count++
        hits.push({ classId: cls.id, index: m.index })
        if (m[0].length === 0) pattern.lastIndex++
      }
    }
    if (count > 0) classes.set(cls.id, (classes.get(cls.id) ?? 0) + count)
  }
  return { hits, classes }
}

function makeExtraClass(extra: string[]): PhraseClass {
  return {
    id: "custom",
    weight: 20,
    containerOnly: false,
    patterns: extra.filter((p) => p.length > 0).map((p) => {
      try {
        return new RegExp(p, "gi")
      } catch {
        return rx(p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      }
    }),
  }
}

/** Find runs of Unicode tag characters and decode them to their ASCII payload. */
function decodeTagRuns(text: string): { index: number; decoded: string }[] {
  const runs: { index: number; decoded: string }[] = []
  let i = 0
  while (i < text.length) {
    const cp = text.codePointAt(i)!
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      const start = i
      let decoded = ""
      while (i < text.length) {
        const cp2 = text.codePointAt(i)!
        if (cp2 >= 0xe0000 && cp2 <= 0xe007f) {
          decoded += String.fromCodePoint(cp2 - 0xe0000)
          i += cp2 > 0xffff ? 2 : 1
        } else break
      }
      if (decoded.trim().length >= 3) runs.push({ index: start, decoded })
    } else {
      i += cp > 0xffff ? 2 : 1
    }
  }
  return runs
}

interface EncodedPayload {
  index: number
  encoded: string
  decodedPhrase: string | null
}

function scanEncodedPayloads(text: string, phraseScan: (s: string) => { hits: PhraseHit[] }): EncodedPayload[] {
  const payloads: EncodedPayload[] = []
  const b64Re = /\b[A-Za-z0-9+/]{80,}={0,2}/g
  for (const m of text.matchAll(b64Re)) {
    const encoded = m[0]
    if (!/[A-Z]/.test(encoded) || !/[a-z]/.test(encoded) || !/[0-9]/.test(encoded)) continue
    const decoded = tryDecodeBase64(encoded)
    if (decoded === null) continue
    const hit = phraseScan(decoded).hits[0]
    payloads.push({ index: m.index ?? 0, encoded, decodedPhrase: hit ? excerptForDecoded(decoded, hit.index) : null })
  }
  const hexRe = /\b[0-9a-fA-F]{80,}\b/g
  for (const m of text.matchAll(hexRe)) {
    const encoded = m[0]
    let decoded = ""
    for (let i = 0; i + 1 < encoded.length; i += 2) {
      const cp = parseInt(encoded.slice(i, i + 2), 16)
      if (cp < 0x20 || cp > 0x10ffff) {
        decoded = ""
        break
      }
      decoded += String.fromCodePoint(cp)
    }
    if (!decoded) continue
    const hit = phraseScan(decoded).hits[0]
    payloads.push({ index: m.index ?? 0, encoded, decodedPhrase: hit ? excerptForDecoded(decoded, hit.index) : null })
  }
  return payloads
}

function excerptForDecoded(decoded: string, index: number): string {
  return excerpt(decoded, index, 30)
}

function tryDecodeBase64(encoded: string): string | null {
  try {
    const bin = atob(encoded)
    let printable = 0
    for (let i = 0; i < bin.length; i++) {
      const c = bin.charCodeAt(i)
      if (c === 9 || c === 10 || c === 13 || (c >= 0x20 && c < 0x7f)) printable++
    }
    if (printable / bin.length < 0.9) return null
    return bin
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// Main scan
// ---------------------------------------------------------------------------

const DEFAULT_MAX_BYTES = 262_144

export function scanText(rawText: string, options: ScanOptions = {}): ScanReport {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES
  const truncated = rawText.length > maxBytes
  const text = truncated ? rawText.slice(0, maxBytes) : rawText

  const detections: Detection[] = []
  const offsets = lineOffsets(text)
  let score = 0
  let concealedPhrase = false
  let decodedPayload = false
  const allExcerpts: string[] = []

  const add = (
    id: CategoryId,
    label: string,
    count: number,
    weight: number,
    indexes: number[],
    concealment: boolean,
    details: string[] = [],
    excerpts: string[] = [],
    cap = Number.POSITIVE_INFINITY,
  ) => {
    if (count <= 0) return
    const capped = Math.min(weight, cap)
    score += capped
    detections.push({
      id,
      label,
      count,
      weight: capped,
      lines: firstLines(offsets, indexes),
      details,
      concealment,
      excerpts,
    })
  }

  // --- Unicode concealment signals -----------------------------------------
  let tagCount = 0
  let zeroCount = 0
  let bidiCount = 0
  let softCount = 0
  const hasLeadingBom = text.charCodeAt(0) === 0xfeff
  const tagIndexes: number[] = []
  const zeroIndexes: number[] = []
  const bidiIndexes: number[] = []
  for (let i = 0; i < text.length; ) {
    const cp = text.codePointAt(i)!
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      tagCount++
      if (tagIndexes.length < 5) tagIndexes.push(i)
    } else if (ZERO_WIDTH.has(cp)) {
      if (!(cp === 0xfeff && hasLeadingBom && i === 0)) {
        zeroCount++
        if (zeroIndexes.length < 5) zeroIndexes.push(i)
      }
    } else if (BIDI.has(cp)) {
      bidiCount++
      if (bidiIndexes.length < 5) bidiIndexes.push(i)
    } else if (cp === SOFT_HYPHEN) {
      softCount++
    }
    i += cp > 0xffff ? 2 : 1
  }

  const tagRuns = tagCount > 0 ? decodeTagRuns(text) : []
  const tagDecodedPhrases = tagRuns
    .map((run) => {
      const hit = scanPhrases(run.decoded, "visible", options.extraPhrases).hits[0]
      return hit ? { run, hit } : null
    })
    .filter((x): x is { run: { index: number; decoded: string }; hit: PhraseHit } => x !== null)

  add(
    "tag-characters",
    "Unicode tag characters (hidden text smuggling)",
    tagCount,
    tagCount * 50,
    tagIndexes,
    true,
    tagDecodedPhrases.length > 0 ? ["decoded hidden text contains instruction phrases"] : [],
    tagDecodedPhrases.map((x) => excerptForDecoded(x.run.decoded, x.hit.index)),
    100,
  )
  if (tagDecodedPhrases.length > 0) {
    decodedPayload = true
    concealedPhrase = true
    allExcerpts.push(...tagDecodedPhrases.map((x) => excerptForDecoded(x.run.decoded, x.hit.index)))
  }

  add(
    "bidi-override",
    "Bidirectional override characters (Trojan Source style)",
    bidiCount,
    bidiCount * 30,
    bidiIndexes,
    true,
    [],
    [],
    90,
  )
  add(
    "hidden-unicode",
    "Zero-width or invisible characters",
    zeroCount + (softCount >= 2 ? softCount : 0),
    zeroCount * 18 + (softCount >= 2 ? Math.min(softCount * 6, 18) : 0),
    zeroIndexes,
    true,
    [],
    [],
    72,
  )

  const puaMatches = [...text.matchAll(PUA_RE)]
  add(
    "private-use",
    "Private-use code points (possible symbol-font encoding, e.g. Wingdings)",
    puaMatches.length,
    puaMatches.length * 3,
    puaMatches.slice(0, 5).map((m) => m.index ?? 0),
    true,
    [],
    [],
    36,
  )

  const vsMatches = [...text.matchAll(VARIATION_RE)]
  if (vsMatches.length >= 3) {
    add(
      "variation-selector",
      "Dense variation selectors (possible hidden data channel)",
      vsMatches.length,
      vsMatches.length * 8,
      vsMatches.slice(0, 5).map((m) => m.index ?? 0),
      true,
      [],
      [],
      32,
    )
  }

  // --- Entity-encoded invisibles -------------------------------------------
  const entityRe = /&#x([0-9a-fA-F]+);?|&#(\d+);?/g
  let entityCount = 0
  const entityIndexes: number[] = []
  const invisibleEntityNames = /&(?:ZeroWidthSpace|zwnj|zwj|word-?joiner|shy|softHyphen|lrm|rlm|lre|rle|lro|rlo|pdf);/gi
  for (const m of text.matchAll(invisibleEntityNames)) {
    entityCount++
    if (entityIndexes.length < 5) entityIndexes.push(m.index ?? 0)
  }
  for (const m of text.matchAll(entityRe)) {
    const decoded = decodeNumericEntity(m[1], m[2])
    if (decoded === undefined) continue
    const cp = decoded.codePointAt(0)!
    if (ZERO_WIDTH.has(cp) || BIDI.has(cp) || (cp >= 0xe0000 && cp <= 0xe007f) || cp === SOFT_HYPHEN) {
      entityCount++
      if (entityIndexes.length < 5) entityIndexes.push(m.index ?? 0)
    }
  }
  add(
    "encoded-invisible-entity",
    "HTML entities encoding invisible characters",
    entityCount,
    entityCount * 18,
    entityIndexes,
    true,
    [],
    [],
    72,
  )

  // --- Hidden styling -------------------------------------------------------
  const stylingHits: { id: string; index: number }[] = []
  for (const styling of HIDDEN_STYLING) {
    styling.pattern.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = styling.pattern.exec(text)) !== null) {
      stylingHits.push({ id: styling.id, index: m.index })
      if (m[0].length === 0) styling.pattern.lastIndex++
    }
  }
  add(
    "hidden-styling",
    "Markup or CSS that hides text from the reader",
    stylingHits.length,
    stylingHits.length * 30,
    stylingHits.slice(0, 5).map((h) => h.index),
    true,
    [...new Set(stylingHits.map((h) => h.id))],
    [],
    90,
  )

  // --- Containers -----------------------------------------------------------
  const containers = extractContainers(text)
  const containerPhraseHits: { container: Container; hit: PhraseHit }[] = []
  for (const container of containers) {
    const { hits } = scanPhrases(container.body, "container", options.extraPhrases)
    for (const hit of hits) containerPhraseHits.push({ container, hit })
  }

  const commentPhraseHits = containerPhraseHits.filter((x) => x.container.kind === "comment")
  add(
    "hidden-comment-phrase",
    "Instruction-like text inside HTML comments",
    commentPhraseHits.length,
    commentPhraseHits.length > 0 ? 45 : 0,
    commentPhraseHits.slice(0, 5).map((x) => x.container.index),
    true,
    [...new Set(commentPhraseHits.map((x) => x.hit.classId))],
    commentPhraseHits.slice(0, 3).map((x) => excerpt(x.container.body, x.hit.index, 30)),
  )
  if (commentPhraseHits.length > 0) concealedPhrase = true

  const metadataPhraseHits = containerPhraseHits.filter((x) => x.container.kind !== "comment" && x.container.kind !== "script")
  add(
    "metadata-phrase",
    "Instruction-like text inside metadata (attributes, meta tags, frontmatter)",
    metadataPhraseHits.length,
    metadataPhraseHits.length > 0 ? 40 : 0,
    metadataPhraseHits.slice(0, 5).map((x) => x.container.index),
    true,
    [...new Set(metadataPhraseHits.map((x) => x.hit.classId))],
    metadataPhraseHits.slice(0, 3).map((x) => excerpt(x.container.body, x.hit.index, 30)),
  )
  if (metadataPhraseHits.length > 0) concealedPhrase = true

  // --- Visible phrases ------------------------------------------------------
  const visibleScan = scanPhrases(text, "visible", options.extraPhrases)
  const visibleClasses = [...visibleScan.classes.entries()]
  let visibleWeight = 0
  for (const [classId, count] of visibleClasses) {
    const cls = findClass(classId)
    visibleWeight += (cls?.weight ?? 20) * Math.min(count, 3)
  }
  // Phrases found only in the normalized (entity/percent-decoded) view count
  // as obfuscated: add a bonus and mark concealment.
  const normalized = normalizeForPhraseScan(text)
  const normalizedScan = normalized === text ? { hits: [] as PhraseHit[] } : scanPhrases(normalized, "visible", options.extraPhrases)
  const obfuscatedOnly = normalizedScan.hits.filter((hit) => !visibleScan.hits.some((v) => v.classId === hit.classId))
  if (obfuscatedOnly.length > 0) {
    visibleWeight += 10 * Math.min(obfuscatedOnly.length, 3)
  }
  const phraseCount = visibleScan.hits.length + obfuscatedOnly.length
  const phraseIndexes = [...visibleScan.hits, ...obfuscatedOnly].slice(0, 5).map((h) => h.index)
  add(
    "instruction-phrase",
    "Instruction-override phrases",
    phraseCount,
    visibleWeight,
    phraseIndexes,
    false,
    [
      ...visibleClasses.map(([classId, count]) => `${classId} \u00d7${count}`),
      ...(obfuscatedOnly.length > 0 ? ["obfuscated via entity/percent encoding"] : []),
    ],
    visibleScan.hits.slice(0, 3).map((h) => excerpt(text, h.index, 30)),
    44,
  )

  // --- Encoded payloads -----------------------------------------------------
  const payloadScan = (s: string) => scanPhrases(s, "visible", options.extraPhrases)
  const payloads = scanEncodedPayloads(text, payloadScan)
  const phrasePayloads = payloads.filter((p) => p.decodedPhrase !== null)
  const plainPayloads = payloads.filter((p) => p.decodedPhrase === null)
  add(
    "encoded-payload",
    "Encoded payloads (base64/hex) hiding instruction phrases",
    phrasePayloads.length,
    phrasePayloads.length > 0 ? 90 : 0,
    phrasePayloads.slice(0, 3).map((p) => p.index),
    true,
    phrasePayloads.length > 0 ? ["decoded payload contains instruction phrases"] : plainPayloads.length > 0 ? ["long encoded blobs present"] : [],
    phrasePayloads.slice(0, 2).map((p) => p.decodedPhrase ?? ""),
  )
  if (phrasePayloads.length > 0) {
    decodedPayload = true
    concealedPhrase = true
    allExcerpts.push(...phrasePayloads.map((p) => p.decodedPhrase ?? ""))
  }
  if (plainPayloads.length > 0) {
    score += Math.min(plainPayloads.length * 5, 15)
    detections.push({
      id: "encoded-payload",
      label: "Long encoded blobs (base64/hex)",
      count: plainPayloads.length,
      weight: Math.min(plainPayloads.length * 5, 15),
      lines: firstLines(offsets, plainPayloads.slice(0, 3).map((p) => p.index)),
      details: ["could not be decoded to readable text"],
      concealment: true,
      excerpts: [],
    })
  }

  // --- Verdict --------------------------------------------------------------
  const dangerousVisible = visibleScan.hits.some((h) => h.classId === "override" || h.classId === "exfiltration" || h.classId === "secrecy")
  const anyConcealment = detections.some((d) => d.concealment && d.count > 0)
  let verdict: Verdict = "clean"
  if (decodedPayload || score >= 80 || (anyConcealment && (concealedPhrase || dangerousVisible))) {
    verdict = "critical"
  } else if (score >= 40) {
    verdict = "likely"
  } else if (score >= 8) {
    verdict = "suspicious"
  }

  return {
    verdict,
    score: Math.round(score),
    detections: detections.sort((a, b) => b.weight - a.weight),
    concealedPhrase,
    decodedPayload,
    scannedBytes: text.length,
    truncated,
  }
}

function findClass(classId: string): PhraseClass | undefined {
  return PHRASE_CLASSES.find((c) => c.id === classId)
}

// ---------------------------------------------------------------------------
// Sanitization
// ---------------------------------------------------------------------------

const REPLACEMENT = "\uFFFD"

export interface SanitizeResult {
  text: string
  notes: string[]
}

/**
 * Strips concealed signals from text without touching visible prose:
 * invisible/bidi/tag/private-use code points, entity-encoded invisibles,
 * phrase-bearing HTML comments, and payloads that decode to instruction
 * phrases. Hidden CSS/markup is flagged but left in place (rewriting markup
 * risks corrupting the document).
 */
export function sanitizeText(text: string, report: ScanReport, options: ScanOptions = {}): SanitizeResult {
  const notes: string[] = []
  let out = text

  const stripCodePoints = () => {
    let removed = 0
    out = Array.from(out)
      .map((ch) => {
        const cp = ch.codePointAt(0)!
        if (ZERO_WIDTH.has(cp) || BIDI.has(cp) || (cp >= 0xe0000 && cp <= 0xe007f) || (cp >= 0xe000 && cp <= 0xf8ff) || (cp >= 0xfe00 && cp <= 0xfe0d)) {
          removed++
          return REPLACEMENT
        }
        if (cp === SOFT_HYPHEN) {
          removed++
          return ""
        }
        return ch
      })
      .join("")
    if (removed > 0) notes.push(`replaced ${removed} invisible/format character${removed === 1 ? "" : "s"} with \uFFFD`)
  }

  const stripEntities = () => {
    let removed = 0
    out = out.replace(/&#x([0-9a-fA-F]+);?|&#(\d+);?/g, (full, hex: string, dec: string) => {
      const decoded = decodeNumericEntity(hex, dec)
      if (decoded === undefined) return full
      const cp = decoded.codePointAt(0)!
      if (ZERO_WIDTH.has(cp) || BIDI.has(cp) || (cp >= 0xe0000 && cp <= 0xe007f) || cp === SOFT_HYPHEN) {
        removed++
        return cp === SOFT_HYPHEN ? "" : REPLACEMENT
      }
      return full
    })
    out = out.replace(/&(?:ZeroWidthSpace|zwnj|zwj|word-?joiner|shy|softHyphen|lrm|rlm|lre|rle|lro|rlo|pdf);/gi, () => {
      removed++
      return REPLACEMENT
    })
    if (removed > 0) notes.push(`neutralized ${removed} entity-encoded invisible character${removed === 1 ? "" : "s"}`)
  }

  const stripPhraseComments = () => {
    let removed = 0
    out = out.replace(/<!--([\s\S]{0,10000}?)-->/g, (full, body: string) => {
      const hits = scanPhrases(body, "container", options.extraPhrases).hits
      if (hits.length === 0) return full
      removed++
      return `<!-- [prompt-blocker: removed HTML comment containing instruction-like text] -->`
    })
    if (removed > 0) notes.push(`removed ${removed} HTML comment${removed === 1 ? "" : "s"} containing instruction-like text`)
  }

  const stripPayloads = () => {
    let removed = 0
    out = out.replace(/\b[A-Za-z0-9+/]{80,}={0,2}/g, (full) => {
      const decoded = tryDecodeBase64(full)
      if (decoded === null) return full
      if (scanPhrases(decoded, "visible", options.extraPhrases).hits.length > 0) {
        removed++
        return "[prompt-blocker: removed encoded payload containing instruction-like text]"
      }
      return full
    })
    out = out.replace(/\b[0-9a-fA-F]{80,}\b/g, (full) => {
      let decoded = ""
      for (let i = 0; i + 1 < full.length; i += 2) {
        const cp = parseInt(full.slice(i, i + 2), 16)
        if (cp < 0x20 || cp > 0x10ffff) {
          decoded = ""
          break
        }
        decoded += String.fromCodePoint(cp)
      }
      if (decoded && scanPhrases(decoded, "visible", options.extraPhrases).hits.length > 0) {
        removed++
        return "[prompt-blocker: removed encoded payload containing instruction-like text]"
      }
      return full
    })
    if (removed > 0) notes.push(`removed ${removed} encoded payload${removed === 1 ? "" : "s"}`)
  }

  if (report.verdict !== "clean") {
    stripCodePoints()
    stripEntities()
    stripPhraseComments()
    stripPayloads()
  }
  return { text: out, notes }
}
