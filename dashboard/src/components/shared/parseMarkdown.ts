import { safeHttpUrl } from './safeUrl'

// 外部データ（OSV の詳細など）のマークダウンを、画面の部品に変換するための解析。
// 新しいライブラリを増やさず、GitHub Advisory で使われる範囲（見出し・段落・箇条書き・表・コード・
// 強調・リンク・引用・区切り線）だけを扱う。結果は構造（木）で返し、画面側が React の要素に直接変換する
// （文字列を HTML として埋め込まないため、XSS が起きない。リンクは http(s) だけ）。
//
// 解析する文章は外部データ（悪意ある入力もありうる）のため、ブラウザが固まらないように、
// 入力の長さ・入れ子の深さに上限を設け、正規表現は「重なる量指定子」を避け、長さを制限している（ReDoS 対策）。

export type Inline =
  | { type: 'text'; text: string }
  | { type: 'code'; text: string }
  | { type: 'strong'; children: Inline[] }
  | { type: 'em'; children: Inline[] }
  | { type: 'link'; href: string; children: Inline[] }

export type Block =
  | { type: 'heading'; level: number; children: Inline[] }
  | { type: 'paragraph'; children: Inline[] }
  | { type: 'code'; text: string }
  | { type: 'list'; ordered: boolean; items: Inline[][] }
  | { type: 'quote'; blocks: Block[] }
  | { type: 'table'; header: Inline[][]; rows: Inline[][][] }
  | { type: 'rule' }

// 解析する文章の最大文字数。これを超える分は省略する
export const MAX_SOURCE_LENGTH = 20_000
// 強調・引用などの入れ子の最大の深さ。これより深い分は、ただの文字として扱う
const MAX_DEPTH = 6
// リンクの文字・URL の最大の長さ（正規表現の探索量を、入力の長さに比例する範囲に抑える）
const MAX_LINK_TEXT = 300
const MAX_LINK_URL = 2000

const ESCAPABLE = '\\`*_{}[]()#+-.!|<>~'

// 前後が英数字でない（単語の途中ではない）か。snake_case の「_」を強調と誤認しないために使う
const isWordChar = (ch: string | undefined) => ch !== undefined && /[A-Za-z0-9]/.test(ch)
const isSpace = (ch: string | undefined) => ch === ' ' || ch === '\t' || ch === '\n'

// 位置 i から始まる記法に一致するかを調べる（rest を切り出さず、sticky で位置を指定する）
function matchAt(re: RegExp, src: string, i: number): RegExpExecArray | null {
  re.lastIndex = i
  return re.exec(src)
}

// 画像 ![alt](url) とリンク [text](url)。文字・URL の長さに上限があり、探索が入力の長さの2乗にならない
const IMAGE = new RegExp(`!\\[([^\\]\\n]{0,${MAX_LINK_TEXT}})\\]\\(([^)\\s]{0,${MAX_LINK_URL}})(?:\\s+"[^"\\n]{0,${MAX_LINK_TEXT}}")?\\)`, 'y')
const LINK = new RegExp(`\\[([^\\]\\n]{1,${MAX_LINK_TEXT}})\\]\\(([^)\\s]{1,${MAX_LINK_URL}})(?:\\s+"[^"\\n]{0,${MAX_LINK_TEXT}}")?\\)`, 'y')

// 位置 start から始まる、長さ len のバッククォートの並びの「閉じ」を探す。見つからなければ -1
function findClosingBackticks(src: string, from: number, len: number): number {
  let pos = from
  while (pos < src.length) {
    const next = src.indexOf('`', pos)
    if (next === -1) return -1
    let end = next
    while (end < src.length && src[end] === '`') end++
    if (end - next === len) return next
    pos = end
  }
  return -1
}

// 文の中の記法（コード・リンク・強調）を解析する
export function parseInline(src: string, depth = 0): Inline[] {
  // 深すぎる入れ子は解釈せず、そのまま文字にする
  if (depth > MAX_DEPTH) return src ? [{ type: 'text', text: src }] : []

  const out: Inline[] = []
  let text = ''
  const flush = () => {
    if (text) {
      out.push({ type: 'text', text })
      text = ''
    }
  }

  let i = 0
  while (i < src.length) {
    const ch = src[i]

    // バックスラッシュによるエスケープ（\* → *）
    if (ch === '\\' && i + 1 < src.length && ESCAPABLE.includes(src[i + 1])) {
      text += src[i + 1]
      i += 2
      continue
    }

    // コード（`code`）。中身は記法を解釈しない
    if (ch === '`') {
      let len = 1
      while (src[i + len] === '`') len++
      const close = findClosingBackticks(src, i + len, len)
      if (close !== -1 && close > i + len) {
        flush()
        out.push({ type: 'code', text: src.slice(i + len, close).trim() })
        i = close + len
        continue
      }
      // 閉じが無ければ、バッククォートの並びをそのまま文字にする
      text += src.slice(i, i + len)
      i += len
      continue
    }

    // 画像（![alt](url)）は読み込まず、代わりの文字だけを出す
    if (ch === '!' && src[i + 1] === '[') {
      const m = matchAt(IMAGE, src, i)
      if (m) {
        text += m[1]
        i += m[0].length
        continue
      }
    }

    // リンク（[text](url)）。http(s) 以外（javascript: など）はリンクにせず、文字だけを出す
    if (ch === '[') {
      const m = matchAt(LINK, src, i)
      if (m) {
        flush()
        const href = safeHttpUrl(m[2])
        const children = parseInline(m[1], depth + 1)
        if (href) out.push({ type: 'link', href, children })
        else out.push(...children)
        i += m[0].length
        continue
      }
    }

    // 太字（**bold** / __bold__）
    if (src.startsWith('**', i) || src.startsWith('__', i)) {
      const marker = src.slice(i, i + 2)
      const end = src.indexOf(marker, i + 2)
      const intraword = marker === '__' && end !== -1 && (isWordChar(src[i - 1]) || isWordChar(src[end + 2]))
      if (end > i + 2 && !intraword) {
        flush()
        out.push({ type: 'strong', children: parseInline(src.slice(i + 2, end), depth + 1) })
        i = end + 2
        continue
      }
    }

    // 斜体（*em* / _em_）。「_」は単語の途中（snake_case）では強調にしない
    if ((ch === '*' || ch === '_') && src[i + 1] !== undefined && !isSpace(src[i + 1])) {
      const end = src.indexOf(ch, i + 1)
      const intraword = ch === '_' && end !== -1 && (isWordChar(src[i - 1]) || isWordChar(src[end + 1]))
      if (end > i + 1 && !isSpace(src[end - 1]) && !intraword) {
        flush()
        out.push({ type: 'em', children: parseInline(src.slice(i + 1, end), depth + 1) })
        i = end + 1
        continue
      }
    }

    text += ch
    i++
  }
  flush()
  return out
}

// ── 行の種類の判定 ─────────────────────────────────────────────
// 正規表現は、量指定子が重ならない（同じ文字を2つの部分が奪い合わない）形にしている

const FENCE = /^ {0,3}(```|~~~)/
// 見出し: # の並び、続けて「空白＋本文」（または行末）。本文末尾の閉じの # は、後で文字単位で取り除く
const HEADING = /^ {0,3}(#{1,6})(?:[ \t]+(.*))?$/
const LIST_ITEM = /^[ \t]*([-*+]|\d{1,9}[.)])[ \t]+(.*)$/
const QUOTE = /^ {0,3}>[ \t]?(.*)$/

// 見出し末尾の閉じの「#」（空白の直後に続く # の並び）を取り除く。C# のような語の途中の # は残す
function stripClosingHashes(text: string): string {
  let end = text.length
  while (end > 0 && (text[end - 1] === ' ' || text[end - 1] === '\t')) end--
  let hashes = end
  while (hashes > 0 && text[hashes - 1] === '#') hashes--
  if (hashes < end && (hashes === 0 || text[hashes - 1] === ' ' || text[hashes - 1] === '\t')) {
    let trimmed = hashes
    while (trimmed > 0 && (text[trimmed - 1] === ' ' || text[trimmed - 1] === '\t')) trimmed--
    return text.slice(0, trimmed)
  }
  return text.slice(0, end)
}

// 区切り線（---・***・___。間に空白があってもよい）。3個以上の同じ記号だけで構成される行
function isRule(line: string): boolean {
  const body = line.trim()
  const marker = body[0]
  if ((marker !== '-' && marker !== '*' && marker !== '_') || line.length - line.trimStart().length > 3) return false
  let count = 0
  for (const ch of body) {
    if (ch === marker) count++
    else if (ch !== ' ' && ch !== '\t') return false
  }
  return count >= 3
}

// 表の区切り行（| --- | :---: |）か。セルごとに「:?---:?」かを調べる
function isTableSeparator(line: string): boolean {
  let body = line.trim()
  if (body.startsWith('|')) body = body.slice(1)
  if (body.endsWith('|')) body = body.slice(0, -1)
  const cells = body.split('|')
  return cells.every(cell => {
    const c = cell.trim()
    const dashes = c.replace(/^:/, '').replace(/:$/, '')
    return dashes.length >= 3 && !/[^-]/.test(dashes)
  })
}

// 表の1行をセルに分ける（行頭・行末の「|」は除く）
function splitRow(line: string): string[] {
  let body = line.trim()
  if (body.startsWith('|')) body = body.slice(1)
  if (body.endsWith('|') && !body.endsWith('\\|')) body = body.slice(0, -1)
  return body.split(/(?<!\\)\|/).map(cell => cell.trim().replace(/\\\|/g, '|'))
}

const startsBlock = (line: string, next: string | undefined) => (
  FENCE.test(line) || HEADING.test(line) || isRule(line) || LIST_ITEM.test(line) || QUOTE.test(line)
  || (line.includes('|') && next !== undefined && isTableSeparator(next))
)

function parseBlocks(src: string, depth: number): Block[] {
  const lines = src.replace(/\r\n?/g, '\n').split('\n')
  const blocks: Block[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]

    if (line.trim() === '') {
      i++
      continue
    }

    // コードブロック（``` で囲む）。閉じる印が無ければ、最後までをコードとして扱う
    const fence = FENCE.exec(line)
    if (fence) {
      const code: string[] = []
      i++
      while (i < lines.length && !lines[i].trimStart().startsWith(fence[1])) {
        code.push(lines[i])
        i++
      }
      i++
      blocks.push({ type: 'code', text: code.join('\n') })
      continue
    }

    const heading = HEADING.exec(line)
    if (heading) {
      blocks.push({
        type: 'heading',
        level: heading[1].length,
        children: parseInline(stripClosingHashes(heading[2] ?? ''), 0),
      })
      i++
      continue
    }

    if (isRule(line)) {
      blocks.push({ type: 'rule' })
      i++
      continue
    }

    // 表（見出し行の次が「---|---」の区切り行）
    if (line.includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
      const header = splitRow(line).map(cell => parseInline(cell))
      const rows: Inline[][][] = []
      i += 2
      while (i < lines.length && lines[i].trim() !== '' && lines[i].includes('|')) {
        rows.push(splitRow(lines[i]).map(cell => parseInline(cell)))
        i++
      }
      blocks.push({ type: 'table', header, rows })
      continue
    }

    // 引用（> で始まる行）。中身は、もう一度マークダウンとして解析する（入れ子の深さには上限がある）
    if (QUOTE.test(line)) {
      const quoted: string[] = []
      while (i < lines.length && QUOTE.test(lines[i])) {
        quoted.push(QUOTE.exec(lines[i])![1])
        i++
      }
      if (depth >= MAX_DEPTH) {
        blocks.push({ type: 'paragraph', children: [{ type: 'text', text: quoted.join(' ') }] })
      } else {
        blocks.push({ type: 'quote', blocks: parseBlocks(quoted.join('\n'), depth + 1) })
      }
      continue
    }

    // 箇条書き（番号つき・なし）。字下げされた続きの行は、直前の項目につなげる
    const item = LIST_ITEM.exec(line)
    if (item) {
      const ordered = /\d/.test(item[1])
      const items: string[] = []
      while (i < lines.length) {
        const m = LIST_ITEM.exec(lines[i])
        if (m) {
          items.push(m[2])
          i++
        } else if (lines[i].trim() !== '' && /^[ \t]/.test(lines[i]) && items.length > 0) {
          items[items.length - 1] += ' ' + lines[i].trim()
          i++
        } else {
          break
        }
      }
      blocks.push({ type: 'list', ordered, items: items.map(it => parseInline(it)) })
      continue
    }

    // 段落（空行・他のブロックが始まるまで）。行は空白でつなぐ
    const para: string[] = []
    while (i < lines.length && lines[i].trim() !== '' && !(para.length > 0 && startsBlock(lines[i], lines[i + 1]))) {
      para.push(lines[i].trim())
      i++
    }
    blocks.push({ type: 'paragraph', children: parseInline(para.join(' ')) })
  }

  return blocks
}

// マークダウン全体を解析する。長すぎる文章は、上限で切って、省略したことを末尾に示す
export function parseMarkdown(src: string): Block[] {
  if (src.length <= MAX_SOURCE_LENGTH) return parseBlocks(src, 0)
  const blocks = parseBlocks(src.slice(0, MAX_SOURCE_LENGTH), 0)
  blocks.push({ type: 'paragraph', children: [{ type: 'em', children: [{ type: 'text', text: '（文章が長いため、以降は省略しました）' }] }] })
  return blocks
}
