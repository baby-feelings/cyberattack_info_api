import { safeHttpUrl } from './safeUrl'

// 外部データ（OSV の詳細など）のマークダウンを、画面の部品に変換するための解析。
// 新しいライブラリを増やさず、GitHub Advisory で使われる範囲（見出し・段落・箇条書き・表・コード・
// 強調・リンク・引用・区切り線）だけを扱う。結果は構造（木）で返し、画面側が React の要素に直接変換する
// （文字列を HTML として埋め込まないため、XSS が起きない。リンクは http(s) だけ）。

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

const ESCAPABLE = /[\\`*_{}[\]()#+\-.!|<>~]/

// 前後が英数字でない（単語の途中ではない）か。snake_case の「_」を強調と誤認しないために使う
const isWordChar = (ch: string | undefined) => ch !== undefined && /[A-Za-z0-9]/.test(ch)

// 文の中の記法（コード・リンク・強調）を解析する
export function parseInline(src: string): Inline[] {
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
    const rest = src.slice(i)

    // バックスラッシュによるエスケープ（\* → *）
    if (ch === '\\' && i + 1 < src.length && ESCAPABLE.test(src[i + 1])) {
      text += src[i + 1]
      i += 2
      continue
    }

    // コード（`code`）。中身は記法を解釈しない
    if (ch === '`') {
      const m = /^(`+)([\s\S]*?[^`])\1(?!`)/.exec(rest)
      if (m) {
        flush()
        out.push({ type: 'code', text: m[2].trim() })
        i += m[0].length
        continue
      }
    }

    // 画像（![alt](url)）は読み込まず、代わりの文字だけを出す
    if (ch === '!' && src[i + 1] === '[') {
      const m = /^!\[([^\]]*)\]\(([^)\s]*)(?:\s+"[^"]*")?\)/.exec(rest)
      if (m) {
        text += m[1]
        i += m[0].length
        continue
      }
    }

    // リンク（[text](url)）。http(s) 以外（javascript: など）はリンクにせず、文字だけを出す
    if (ch === '[') {
      const m = /^\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/.exec(rest)
      if (m) {
        flush()
        const href = safeHttpUrl(m[2])
        const children = parseInline(m[1])
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
      const intraword = marker === '__' && (isWordChar(src[i - 1]) || isWordChar(src[end + 2]))
      if (end > i + 2 && !intraword) {
        flush()
        out.push({ type: 'strong', children: parseInline(src.slice(i + 2, end)) })
        i = end + 2
        continue
      }
    }

    // 斜体（*em* / _em_）。「_」は単語の途中（snake_case）では強調にしない
    if ((ch === '*' || ch === '_') && src[i + 1] !== undefined && !/\s/.test(src[i + 1])) {
      const end = src.indexOf(ch, i + 1)
      const intraword = ch === '_' && (isWordChar(src[i - 1]) || isWordChar(src[end + 1]))
      if (end > i + 1 && !/\s/.test(src[end - 1]) && !intraword) {
        flush()
        out.push({ type: 'em', children: parseInline(src.slice(i + 1, end)) })
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

const FENCE = /^\s{0,3}(```|~~~)/
const HEADING = /^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/
const RULE = /^\s{0,3}([-*_])(\s*\1){2,}\s*$/
const LIST_ITEM = /^\s*([-*+]|\d+[.)])\s+(.*)$/
const QUOTE = /^\s{0,3}>\s?(.*)$/
const TABLE_SEPARATOR = /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/

// 表の1行をセルに分ける（行頭・行末の「|」は除く）
function splitRow(line: string): string[] {
  let body = line.trim()
  if (body.startsWith('|')) body = body.slice(1)
  if (body.endsWith('|') && !body.endsWith('\\|')) body = body.slice(0, -1)
  return body.split(/(?<!\\)\|/).map(cell => cell.trim().replace(/\\\|/g, '|'))
}

const startsBlock = (line: string, next: string | undefined) => (
  FENCE.test(line) || HEADING.test(line) || RULE.test(line) || LIST_ITEM.test(line) || QUOTE.test(line)
  || (line.includes('|') && next !== undefined && TABLE_SEPARATOR.test(next))
)

// マークダウン全体を解析する
export function parseMarkdown(src: string): Block[] {
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
      blocks.push({ type: 'heading', level: heading[1].length, children: parseInline(heading[2]) })
      i++
      continue
    }

    if (RULE.test(line)) {
      blocks.push({ type: 'rule' })
      i++
      continue
    }

    // 表（見出し行の次が「---|---」の区切り行）
    if (line.includes('|') && i + 1 < lines.length && TABLE_SEPARATOR.test(lines[i + 1])) {
      const header = splitRow(line).map(parseInline)
      const rows: Inline[][][] = []
      i += 2
      while (i < lines.length && lines[i].trim() !== '' && lines[i].includes('|')) {
        rows.push(splitRow(lines[i]).map(parseInline))
        i++
      }
      blocks.push({ type: 'table', header, rows })
      continue
    }

    // 引用（> で始まる行）。中身は、もう一度マークダウンとして解析する
    if (QUOTE.test(line)) {
      const quoted: string[] = []
      while (i < lines.length && QUOTE.test(lines[i])) {
        quoted.push(QUOTE.exec(lines[i])![1])
        i++
      }
      blocks.push({ type: 'quote', blocks: parseMarkdown(quoted.join('\n')) })
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
        } else if (lines[i].trim() !== '' && /^\s+/.test(lines[i]) && items.length > 0) {
          items[items.length - 1] += ' ' + lines[i].trim()
          i++
        } else {
          break
        }
      }
      blocks.push({ type: 'list', ordered, items: items.map(parseInline) })
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
