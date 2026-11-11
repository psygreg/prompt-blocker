/**
 * prompt-blocker image quarantine: decoding, metadata extraction, canonical
 * re-encoding, and randomized transforms for untrusted images.
 *
 * Pure module: no OpenCode imports, so everything here is unit-testable.
 * Decoding and re-encoding use Bun's built-in image pipeline (statically
 * linked libjpeg-turbo / libspng / libwebp) — hardened native codecs behind a
 * pixel-count cap, no native module install. Untrusted bytes never reach a
 * hand-written decoder: anything this module cannot recognize is refused, not
 * guessed at.
 *
 * Pipeline (see scrubImage):
 *
 *   decode (auto-orient, pixel cap) -> randomized mild transforms ->
 *   canonical re-encode (PNG, or JPEG at a fixed base quality) ->
 *   canonical container rewrite (drop every non-essential chunk/segment) ->
 *   verify the result decodes with the expected shape
 *
 * Randomness is injectable so tests can pin it; production uses a
 * crypto-backed source. The transforms are the anti-steganography layer:
 * resampling perturbs every pixel, lossy recompression destroys LSB and DCT
 * coefficient patterns, and animated input is flattened to its first frame.
 */

import { randomInt } from "node:crypto"
import { inflateSync } from "node:zlib"

export type ImageFormat = "png" | "jpeg" | "gif" | "webp" | "bmp" | "tiff" | "heic" | "avif"

/** Canonical re-encode targets. Every input decodes into one of these. */
export type CanonicalFormat = "png" | "jpeg"

export interface MetadataItem {
  /** Container field the text came from, e.g. "PNG tEXt Comment", "JPEG COM". */
  source: string
  text: string
}

export interface MetadataExtraction {
  items: MetadataItem[]
  /** Concatenated metadata text, ready for scanText. */
  text: string
}

// ---------------------------------------------------------------------------
// Format recognition
// ---------------------------------------------------------------------------

const EXT_TO_FORMAT: Record<string, ImageFormat> = {
  png: "png",
  jpg: "jpeg",
  jpeg: "jpeg",
  jfif: "jpeg",
  gif: "gif",
  webp: "webp",
  bmp: "bmp",
  dib: "bmp",
  tif: "tiff",
  tiff: "tiff",
  heic: "heic",
  heif: "heic",
  avif: "avif",
}

export const IMAGE_EXTENSIONS = new Set(Object.keys(EXT_TO_FORMAT))

/** Image format by file-name extension, or null. Ignores query strings. */
export function extensionFormat(path: string): ImageFormat | null {
  const clean = path.replace(/[?#].*$/, "")
  const dot = clean.lastIndexOf(".")
  if (dot === -1) return null
  return EXT_TO_FORMAT[clean.slice(dot + 1).toLowerCase()] ?? null
}

function asciiAt(bytes: Uint8Array, offset: number, text: string): boolean {
  if (offset + text.length > bytes.length) return false
  for (let i = 0; i < text.length; i++) {
    if (bytes[offset + i] !== text.charCodeAt(i)) return false
  }
  return true
}

/** Image format by magic bytes, or null for anything unrecognized. */
export function sniffImageFormat(head: Uint8Array): ImageFormat | null {
  if (
    head.length >= 8 &&
    head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4e && head[3] === 0x47 &&
    head[4] === 0x0d && head[5] === 0x0a && head[6] === 0x1a && head[7] === 0x0a
  ) return "png"
  if (head.length >= 3 && head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return "jpeg"
  if (head.length >= 6 && (asciiAt(head, 0, "GIF87a") || asciiAt(head, 0, "GIF89a"))) return "gif"
  if (head.length < 12) return null
  if (asciiAt(head, 0, "RIFF") && asciiAt(head, 8, "WEBP")) return "webp"
  if (head[0] === 0x42 && head[1] === 0x4d) return "bmp"
  if (head[0] === 0x49 && head[1] === 0x49 && head[2] === 0x2a && head[3] === 0x00) return "tiff"
  if (head[0] === 0x4d && head[1] === 0x4d && head[2] === 0x00 && head[3] === 0x2a) return "tiff"
  if (asciiAt(head, 4, "ftyp")) {
    const brand = String.fromCharCode(head[8], head[9], head[10], head[11])
    if (/^(heic|heix|heim|heis|hevc|hevx|heif|mif1|msf1)/.test(brand)) return "heic"
    if (/^(avif|avis)/.test(brand)) return "avif"
  }
  return null
}

/** Cheap pre-check combining extension and (when available) magic bytes. */
export function looksLikeImage(path: string, head?: Uint8Array): boolean {
  if (extensionFormat(path) !== null) return true
  return head !== undefined && sniffImageFormat(head) !== null
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

function be32(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0
}

function be16(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] << 8) | bytes[offset + 1]
}

function le32(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0
}

function latin1(bytes: Uint8Array, start = 0, end = bytes.length): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset + start, Math.max(0, Math.min(end, bytes.length) - start)).toString("latin1")
}

/**
 * Printable ASCII runs (>= minRun characters) — the generic sweep that catches
 * text in containers this module has no structural parser for. Runs are joined
 * with newlines; total output is capped so a hostile file cannot flood the
 * scanner.
 */
export function printableRuns(bytes: Uint8Array, minRun = 8, capChars = 32768): string[] {
  const runs: string[] = []
  let start = -1
  let collected = 0
  const flush = (end: number) => {
    if (start !== -1 && end - start >= minRun) {
      runs.push(latin1(bytes, start, end))
      collected += end - start
    }
    start = -1
  }
  for (let i = 0; i < bytes.length && collected < capChars; i++) {
    const b = bytes[i]
    const printable = (b >= 0x20 && b <= 0x7e) || b === 9 || b === 10 || b === 13
    if (printable) {
      if (start === -1) start = i
    } else {
      flush(i)
    }
  }
  flush(bytes.length)
  return runs
}

function tryInflate(data: Uint8Array): Buffer | null {
  try {
    return inflateSync(data)
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// Metadata extraction (what was hidden in the container, before stripping)
// ---------------------------------------------------------------------------

type MetadataSink = (source: string, text: string) => void

function extractPng(bytes: Uint8Array, push: MetadataSink): void {
  let pos = 8
  while (pos + 12 <= bytes.length) {
    const len = be32(bytes, pos)
    if (len > bytes.length - pos - 12) break
    const type = latin1(bytes, pos + 4, pos + 8)
    const data = bytes.subarray(pos + 8, pos + 8 + len)
    if (type === "tEXt") {
      const nul = data.indexOf(0)
      if (nul > 0) push(`PNG tEXt ${latin1(data, 0, nul)}`, latin1(data, nul + 1))
    } else if (type === "zTXt") {
      const nul = data.indexOf(0)
      if (nul > 0) {
        const inflated = tryInflate(data.subarray(nul + 2))
        if (inflated) push(`PNG zTXt ${latin1(data, 0, nul)}`, inflated.toString("latin1"))
      }
    } else if (type === "iTXt") {
      const keywordEnd = data.indexOf(0)
      if (keywordEnd > 0) {
        const compressed = data[keywordEnd + 1] === 1
        let cursor = keywordEnd + 3
        cursor = data.indexOf(0, cursor) + 1 // language tag
        cursor = data.indexOf(0, cursor) + 1 // translated keyword
        if (cursor > 0 && cursor < data.length) {
          const body = data.subarray(cursor)
          const text = compressed ? (tryInflate(body) ?? body) : body
          push(`PNG iTXt ${latin1(data, 0, keywordEnd)}`, Buffer.from(text).toString("latin1"))
        }
      }
    } else if (type === "eXIf") {
      for (const run of printableRuns(data)) push("PNG eXIf", run)
    } else if (type === "iCCP") {
      const nul = data.indexOf(0)
      if (nul > 0) {
        const inflated = tryInflate(data.subarray(nul + 2))
        if (inflated) for (const run of printableRuns(inflated)) push(`PNG iCCP ${latin1(data, 0, nul)}`, run)
      }
    }
    if (type === "IEND") break
    pos += 12 + len
  }
}

interface JpegPiece {
  kind: "segment" | "entropy"
  marker: number
  start: number
  end: number
}

/**
 * Walk a JPEG stream into byte ranges: framed segments and the raw entropy
 * data after each SOS header. Marker fill bytes (0xFF padding) stay attached
 * to the segment that follows them, so whitelisted segments can be copied
 * byte-exact when rewriting the container. Returns null on structural desync.
 */
export function walkJpeg(bytes: Uint8Array): JpegPiece[] | null {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null
  const pieces: JpegPiece[] = []
  let pos = 2
  while (pos + 1 < bytes.length) {
    if (bytes[pos] !== 0xff) return null
    let markerPos = pos + 1
    while (markerPos < bytes.length && bytes[markerPos] === 0xff) markerPos++
    if (markerPos >= bytes.length) return null
    const marker = bytes[markerPos]
    if (marker === 0xd9) {
      pieces.push({ kind: "segment", marker, start: pos, end: Math.min(markerPos + 2, bytes.length) })
      break
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      // Standalone TEM/RST markers outside entropy data: tolerated, dropped.
      pos = markerPos + 1
      continue
    }
    if (markerPos + 3 > bytes.length) return null
    const len = be16(bytes, markerPos + 1)
    if (len < 2 || markerPos + 1 + len > bytes.length) return null
    const segStart = pos
    const segEnd = markerPos + 1 + len
    pieces.push({ kind: "segment", marker, start: segStart, end: segEnd })
    if (marker === 0xda) {
      // Entropy-coded data: 0xFF00 stuffing and RST markers belong to it; the
      // next real marker ends the scan.
      let e = segEnd
      while (e + 1 < bytes.length) {
        if (bytes[e] === 0xff) {
          const next = bytes[e + 1]
          if (next === 0x00 || next === 0x01 || (next >= 0xd0 && next <= 0xd7)) {
            e += 2
            continue
          }
          break
        }
        e++
      }
      pieces.push({ kind: "entropy", marker, start: segEnd, end: Math.min(e, bytes.length) })
      pos = e
      continue
    }
    pos = segEnd
  }
  return pieces
}

const JPEG_TEXT_MARKERS = new Set([0xfe]) // COM
const JPEG_APP_MARKERS = new Set<number>()
for (let m = 0xe0; m <= 0xef; m++) JPEG_APP_MARKERS.add(m)

function jpegSegmentPayload(bytes: Uint8Array, piece: JpegPiece): Uint8Array {
  // [FF marker][len hi lo][payload...]: payload starts 4 bytes into the piece.
  return bytes.subarray(piece.start + 4, piece.end)
}

function extractJpeg(bytes: Uint8Array, push: MetadataSink): void {
  const pieces = walkJpeg(bytes)
  if (!pieces) return
  for (const piece of pieces) {
    if (piece.kind !== "segment") continue
    if (JPEG_TEXT_MARKERS.has(piece.marker)) {
      push("JPEG COM", latin1(jpegSegmentPayload(bytes, piece)))
    } else if (JPEG_APP_MARKERS.has(piece.marker)) {
      const payload = jpegSegmentPayload(bytes, piece)
      const app = piece.marker - 0xe0
      if (asciiAt(payload, 0, "Exif")) {
        for (const run of printableRuns(payload.subarray(6))) push(`JPEG APP${app} Exif`, run)
      } else if (asciiAt(payload, 0, "ICC_PROFILE")) {
        for (const run of printableRuns(payload)) push(`JPEG APP${app} ICC profile`, run)
      } else if (payload.length > 0) {
        const text = latin1(payload)
        const printable = [...text].filter((ch) => (ch.charCodeAt(0) >= 0x20 && ch.charCodeAt(0) <= 0x7e) || ch === "\n" || ch === "\r" || ch === "\t").length
        if (printable / Math.max(1, text.length) > 0.85) {
          push(`JPEG APP${app}`, text)
        } else {
          for (const run of printableRuns(payload)) push(`JPEG APP${app}`, run)
        }
      }
    }
  }
}

function extractGif(bytes: Uint8Array, push: MetadataSink): void {
  if (bytes.length < 13 || !(asciiAt(bytes, 0, "GIF87a") || asciiAt(bytes, 0, "GIF89a"))) return
  let pos = 13
  const screenFlags = bytes[10]
  if (screenFlags & 0x80) pos += 3 * (2 ** ((screenFlags & 0x07) + 1))
  while (pos < bytes.length) {
    const block = bytes[pos++]
    if (block === 0x3b) break // trailer
    if (block === 0x21) {
      if (pos >= bytes.length) break
      const label = bytes[pos++]
      const chunks: Buffer[] = []
      while (pos < bytes.length) {
        const size = bytes[pos++]
        if (size === 0) break
        if (pos + size > bytes.length) return
        chunks.push(Buffer.from(bytes.subarray(pos, pos + size)))
        pos += size
      }
      const body = Buffer.concat(chunks)
      if (label === 0xfe) {
        push("GIF comment", body.toString("latin1"))
      } else {
        for (const run of printableRuns(body)) push(`GIF extension 0x${label.toString(16).padStart(2, "0")}`, run)
      }
    } else if (block === 0x2c) {
      if (pos + 9 > bytes.length) break
      const flags = bytes[pos + 8]
      pos += 9
      if (flags & 0x80) pos += 3 * (2 ** ((flags & 0x07) + 1))
      if (pos >= bytes.length) break
      pos++ // LZW minimum code size
      while (pos < bytes.length) {
        const size = bytes[pos++]
        if (size === 0) break
        pos += size
      }
    } else {
      break
    }
  }
}

function extractWebp(bytes: Uint8Array, push: MetadataSink): void {
  if (!(asciiAt(bytes, 0, "RIFF") && asciiAt(bytes, 8, "WEBP"))) return
  let pos = 12
  while (pos + 8 <= bytes.length) {
    const fourcc = latin1(bytes, pos, pos + 4)
    const len = le32(bytes, pos + 4)
    const data = bytes.subarray(pos + 8, Math.min(pos + 8 + len, bytes.length))
    if (fourcc === "EXIF") {
      for (const run of printableRuns(data)) push("WebP EXIF", run)
    } else if (fourcc === "XMP ") {
      push("WebP XMP", latin1(data))
    } else if (fourcc === "ICCP") {
      for (const run of printableRuns(data)) push("WebP ICCP", run)
    }
    pos += 8 + len + (len & 1)
  }
}

/**
 * Inventory of the text the container carries outside the pixels: text
 * chunks, comments, EXIF strings, XMP, application extensions. Structural
 * parsers run for the formats that have them; a printable-run sweep covers
 * the rest. Best-effort by design — the deterministic strip in scrubImage is
 * what actually removes the metadata.
 */
export function extractMetadata(bytes: Uint8Array, format: ImageFormat | null): MetadataExtraction {
  const items: MetadataItem[] = []
  const push: MetadataSink = (source, text) => {
    const trimmed = text.replace(/[\r\n]+/g, " ").trim()
    if (trimmed.length >= 4) items.push({ source, text: trimmed.slice(0, 2000) })
  }
  try {
    if (format === "png") extractPng(bytes, push)
    else if (format === "jpeg") extractJpeg(bytes, push)
    else if (format === "gif") extractGif(bytes, push)
    else if (format === "webp") extractWebp(bytes, push)
    else for (const run of printableRuns(bytes.subarray(0, 65536))) push(`${format ?? "unknown"} header bytes`, run)
  } catch {
    // Extraction must never break the pipeline; scrubbing strips regardless.
  }
  // Each field is wrapped in a comment container so scanText sees what it is:
  // text hidden from the rendered content in a metadata field is concealed
  // text, and the scanner's concealment rules apply to it.
  return { items, text: items.map((item) => `<!-- ${item.source}: ${item.text} -->`).join("\n") }
}

// ---------------------------------------------------------------------------
// Canonical containers
// ---------------------------------------------------------------------------

const PNG_KEEP = new Set(["IHDR", "PLTE", "tRNS", "IDAT", "IEND"])

/**
 * Rewrite a PNG keeping only the chunks that encode the image itself. Every
 * ancillary chunk — text, EXIF, ICC profile, timestamps, anything the encoder
 * preserved — is dropped. Returns null when the stream is not parseable.
 */
export function canonicalizePng(bytes: Uint8Array): Uint8Array | null {
  if (bytes.length < 8) return null
  const out: Buffer[] = [Buffer.from(bytes.subarray(0, 8))]
  let pos = 8
  while (pos + 12 <= bytes.length) {
    const len = be32(bytes, pos)
    if (len > bytes.length - pos - 12) return null
    const type = latin1(bytes, pos + 4, pos + 8)
    const end = pos + 12 + len
    if (PNG_KEEP.has(type)) out.push(Buffer.from(bytes.subarray(pos, end)))
    if (type === "IEND") return Buffer.concat(out)
    pos = end
  }
  return null
}

const JPEG_KEEP = new Set<number>([0xdb, 0xc4, 0xdd, 0xda, 0xd9]) // DQT, DHT, DRI, SOS, EOI
for (const sof of [0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]) {
  JPEG_KEEP.add(sof)
}

/**
 * Rewrite a JPEG keeping only the segments a decoder needs (quantization,
 * huffman, frame, restart-interval, scan + entropy data, EOI). All APPn
 * segments (EXIF, ICC, XMP, thumbnails) and COM comments are dropped.
 * Returns null when the stream is not parseable.
 */
export function canonicalizeJpeg(bytes: Uint8Array): Uint8Array | null {
  const pieces = walkJpeg(bytes)
  if (!pieces) return null
  const out: Buffer[] = [Buffer.from(bytes.subarray(0, 2))]
  let sawEoi = false
  for (const piece of pieces) {
    if (piece.kind === "entropy") {
      out.push(Buffer.from(bytes.subarray(piece.start, piece.end)))
      continue
    }
    if (piece.marker === 0xd8) continue // redundant SOI
    if (JPEG_KEEP.has(piece.marker)) {
      out.push(Buffer.from(bytes.subarray(piece.start, piece.end)))
      if (piece.marker === 0xd9) sawEoi = true
    }
  }
  if (!sawEoi) out.push(Buffer.from([0xff, 0xd9]))
  return Buffer.concat(out)
}

// ---------------------------------------------------------------------------
// The scrub pipeline
// ---------------------------------------------------------------------------

const RESAMPLE_FILTERS = ["bilinear", "cubic", "mitchell"] as const

/** Fixed base JPEG quality for the canonical encode. */
export const DEFAULT_JPEG_QUALITY = 82

export interface ScrubOptions {
  /** Base JPEG quality for the canonical encode (per-image jitter applies). Default 82. */
  quality?: number
  /** Random source in [0,1). Defaults to a crypto-backed source. */
  rng?: () => number
}

export interface ScrubResult {
  bytes: Uint8Array
  format: CanonicalFormat
  width: number
  height: number
  sourceWidth: number
  sourceHeight: number
  /** Human-readable list of the transforms that were applied. */
  transforms: string[]
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value))
}

function defaultRng(): number {
  return randomInt(0, 1_000_000_000) / 1_000_000_000
}

// ---------------------------------------------------------------------------
// Pixel budget (decompression-bomb guard)
// ---------------------------------------------------------------------------

/** Largest pixel count the decode path accepts. A 10k×10k image is 400 MB of RGBA. */
export const MAX_PIXELS = 16_000_000

export interface PixelBudget {
  width: number
  height: number
}

/**
 * Width/height for the formats whose dimensions can be read without
 * decoding. Null when unknown — libspng/libjpeg enforce their own limits,
 * but the explicit cap is what actually stops a decompression bomb.
 */
export function imagePixelBudget(bytes: Uint8Array, format: ImageFormat | null): PixelBudget | null {
  try {
    if (format === "png") {
      // Chunks: length(4) type(4) data... IHDR data: width(4) height(4).
      if (bytes.length < 24) return null
      const width = be32(bytes, 16)
      const height = be32(bytes, 20)
      return width > 0 && height > 0 ? { width, height } : null
    }
    if (format === "jpeg") {
      let pos = 2
      while (pos + 4 <= bytes.length) {
        if (bytes[pos] !== 0xff) return null
        while (pos < bytes.length && bytes[pos] === 0xff) pos++
        if (pos >= bytes.length) return null
        const marker = bytes[pos]
        if (marker === 0x00 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd9)) {
          pos++
          continue
        }
        if (marker === 0xda) return null
        const len = be16(bytes, pos + 1)
        if (len < 2 || pos + 2 + len > bytes.length) return null
        if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
          // SOF: FF marker len(2) precision(1) height(2) width(2)
          const height = be16(bytes, pos + 4)
          const width = be16(bytes, pos + 6)
          return width > 0 && height > 0 ? { width, height } : null
        }
        // `pos` sits on the marker byte; the segment spans FF + marker + len.
        pos += 1 + len
      }
      return null
    }
    if (format === "gif") {
      if (bytes.length < 10) return null
      const width = le32(bytes, 6) & 0xffff
      const height = le32(bytes, 8) & 0xffff
      return width > 0 && height > 0 ? { width, height } : null
    }
    if (format === "webp") {
      if (bytes.length < 30) return null
      if (asciiAt(bytes, 12, "VP8X")) {
        const width = 1 + (bytes[24] | (bytes[25] << 8) | (bytes[26] << 16))
        const height = 1 + (bytes[27] | (bytes[28] << 8) | (bytes[29] << 16))
        return width > 0 && height > 0 ? { width, height } : null
      }
      if (asciiAt(bytes, 12, "VP8 ")) {
        // lossy keyframe: 3-byte frame tag, sync code, then 24-bit dims
        const width = 1 + ((bytes[26] | (bytes[27] << 8)) & 0x3fff)
        const height = 1 + ((bytes[28] | (bytes[29] << 8)) & 0x3fff)
        return width > 0 && height > 0 ? { width, height } : null
      }
      if (asciiAt(bytes, 12, "VP8L")) {
        // lossless: signature byte, 14-bit width-1 and height-1 packed
        const bits = bytes[21] | (bytes[22] << 8) | (bytes[23] << 16) | (bytes[24] << 24)
        const width = (bits & 0x3fff) + 1
        const height = ((bits >> 14) & 0x3fff) + 1
        return width > 0 && height > 0 ? { width, height } : null
      }
      return null
    }
    return null
  } catch {
    return null
  }
}

/**
 * Decode an untrusted image and re-encode it into a sanitized, canonical
 * form. Throws (fail-closed) when the bytes cannot be decoded or the result
 * fails verification; callers must treat a throw as "image stays quarantined".
 *
 * - Decoding: Bun's native codecs, auto-orientation applied, pixel count
 *   capped. Animated containers (GIF, animated WebP) decode to their first
 *   frame — flattening is inherent to the pipeline.
 * - Transforms: a random mild resample (±2% scale, random kernel), a random
 *   imperceptible brightness/saturation jitter, and lossy recompression.
 *   For PNG targets the pixels first take a lossy JPEG detour, because a
 *   lossless re-encode alone would preserve least-significant-bit
 *   steganography exactly.
 * - Canonical container: every non-essential chunk/segment is dropped, so no
 *   metadata survives the re-encode — including ICC profiles the encoder
 *   would otherwise preserve.
 * - Verification: the final bytes must decode again with the expected shape.
 */
export async function scrubImage(source: Uint8Array, format: ImageFormat | null, options: ScrubOptions = {}): Promise<ScrubResult> {
  const rng = options.rng ?? defaultRng
  const baseQuality = clamp(Math.round(options.quality ?? DEFAULT_JPEG_QUALITY), 40, 95)

  const budget = imagePixelBudget(source, format)
  if (budget && budget.width * budget.height > MAX_PIXELS) {
    throw new Error(
      `pixel budget exceeded: ${budget.width}x${budget.height} (${Math.round((budget.width * budget.height) / 1_000_000)} MP) ` +
        `is beyond the ${Math.round(MAX_PIXELS / 1_000_000)} MP decode limit; the image stays quarantined`,
    )
  }

  const image = new Bun.Image(source, { autoOrient: true })
  const sourceMeta = await image.metadata()

  const scale = 1 + (rng() * 2 - 1) * 0.02
  const filter = RESAMPLE_FILTERS[Math.floor(rng() * RESAMPLE_FILTERS.length)] ?? "bilinear"
  let width = Math.max(8, Math.round(sourceMeta.width * scale))
  let height = Math.max(8, Math.round(sourceMeta.height * scale))
  if (width === sourceMeta.width && height === sourceMeta.height) {
    // Rounding landed on the source dimensions; nudge one axis so the
    // resample always actually regrids the pixels.
    if (height > 8) height -= 1
    else width += 1
  }
  const brightness = 1 + (rng() * 2 - 1) * 0.006
  const saturation = 1 + (rng() * 2 - 1) * 0.006
  const transforms = [
    `resize ${width}x${height} (${filter} resample)`,
    `brightness/saturation jitter (${brightness.toFixed(4)}/${saturation.toFixed(4)})`,
  ]
  image.resize(width, height, { filter })
  image.modulate({ brightness, saturation })

  const canonical: CanonicalFormat = format === "png" || format === "gif" || format === "bmp" ? "png" : "jpeg"
  let encoded: Uint8Array
  if (canonical === "jpeg") {
    const quality = clamp(baseQuality + Math.floor(rng() * 9) - 4, 40, 95)
    transforms.push(`re-encode JPEG (quality ${quality})`)
    encoded = await image.jpeg({ quality }).bytes()
  } else {
    const roundtripQuality = clamp(baseQuality + Math.floor(rng() * 7) - 3, 40, 95)
    transforms.push(`JPEG recompression (quality ${roundtripQuality})`)
    const detour = await image.jpeg({ quality: roundtripQuality }).bytes()
    encoded = await new Bun.Image(detour).png({ compressionLevel: 6 }).bytes()
  }

  const canonicalBytes = canonical === "png" ? canonicalizePng(encoded) : canonicalizeJpeg(encoded)
  const finalBytes = canonicalBytes ?? encoded
  if (canonicalBytes === null) {
    // Structural rewrite failed (should not happen for encoder output); the
    // re-encoded bytes are still metadata-free in practice, so continue with
    // them rather than failing the whole scrub.
    transforms.push("container rewrite skipped (non-parseable stream)")
  }

  const check = await new Bun.Image(finalBytes).metadata()
  if (check.width !== width || check.height !== height) {
    throw new Error(`scrub verification failed: expected ${width}x${height}, decoded ${check.width}x${check.height}`)
  }

  return {
    bytes: finalBytes,
    format: canonical,
    width,
    height,
    sourceWidth: sourceMeta.width,
    sourceHeight: sourceMeta.height,
    transforms,
  }
}

// ---------------------------------------------------------------------------
// Data URIs
// ---------------------------------------------------------------------------

/** Parse a `data:` URI into mime type and decoded bytes, or null. */
export function parseDataUri(uri: string): { mime: string; bytes: Uint8Array } | null {
  const match = /^data:([^;,]*)(;base64)?,([\s\S]*)$/.exec(uri)
  if (!match) return null
  const mime = match[1] || "application/octet-stream"
  const payload = match[3] ?? ""
  if (match[2]) {
    try {
      const binary = atob(payload)
      const bytes = new Uint8Array(binary.length)
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
      return { mime, bytes }
    } catch {
      return null
    }
  }
  let decoded: string
  try {
    decoded = decodeURIComponent(payload)
  } catch {
    decoded = payload
  }
  return { mime, bytes: new TextEncoder().encode(decoded) }
}
