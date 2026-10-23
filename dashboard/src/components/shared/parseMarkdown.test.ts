import { describe, it, expect } from 'vitest'
import { parseInline, parseMarkdown, MAX_SOURCE_LENGTH } from './parseMarkdown'

describe('parseInline', () => {
  it('keeps plain text as it is', () => {
    expect(parseInline('hello world')).toEqual([{ type: 'text', text: 'hello world' }])
  })

  it('parses code spans, and does not interpret markup inside them', () => {
    expect(parseInline('use `**im.load()**` here')).toEqual([
      { type: 'text', text: 'use ' },
      { type: 'code', text: '**im.load()**' },
      { type: 'text', text: ' here' },
    ])
  })

  it('parses bold and italic', () => {
    expect(parseInline('a **b** c *d* e')).toEqual([
      { type: 'text', text: 'a ' },
      { type: 'strong', children: [{ type: 'text', text: 'b' }] },
      { type: 'text', text: ' c ' },
      { type: 'em', children: [{ type: 'text', text: 'd' }] },
      { type: 'text', text: ' e' },
    ])
  })

  it('does not treat underscores inside a word (snake_case) as emphasis', () => {
    expect(parseInline('call my_func_name now')).toEqual([{ type: 'text', text: 'call my_func_name now' }])
  })

  it('treats a lone asterisk or an unclosed marker as text', () => {
    expect(parseInline('2 * 3 and **open')).toEqual([{ type: 'text', text: '2 * 3 and **open' }])
  })

  it('unescapes backslash-escaped characters', () => {
    expect(parseInline('a \\*not bold\\* b')).toEqual([{ type: 'text', text: 'a *not bold* b' }])
  })

  it('parses http(s) links', () => {
    expect(parseInline('see [the advisory](https://example.com/a)')).toEqual([
      { type: 'text', text: 'see ' },
      { type: 'link', href: 'https://example.com/a', children: [{ type: 'text', text: 'the advisory' }] },
    ])
  })

  it('does not make a link of a non-http(s) URL (javascript:, data:), keeping only the text', () => {
    expect(parseInline('[click](javascript:alert(1))')).not.toContainEqual(expect.objectContaining({ type: 'link' }))
    expect(parseInline('[click](javascript:alert)')).toEqual([{ type: 'text', text: 'click' }])
    expect(parseInline('[x](data:text/html,<b>)')).toEqual([{ type: 'text', text: 'x' }])
  })

  it('does not load images: only the alt text is kept', () => {
    expect(parseInline('![logo](https://example.com/a.png) end')).toEqual([{ type: 'text', text: 'logo end' }])
  })

  it('leaves HTML-like text as text', () => {
    expect(parseInline('<script>alert(1)</script>')).toEqual([{ type: 'text', text: '<script>alert(1)</script>' }])
  })
})

describe('parseMarkdown', () => {
  it('parses headings with their level', () => {
    expect(parseMarkdown('### Summary\n## Affected wheels')).toEqual([
      { type: 'heading', level: 3, children: [{ type: 'text', text: 'Summary' }] },
      { type: 'heading', level: 2, children: [{ type: 'text', text: 'Affected wheels' }] },
    ])
  })

  it('joins consecutive lines of a paragraph with a space, and splits paragraphs on blank lines', () => {
    expect(parseMarkdown('line one\nline two\n\nsecond paragraph')).toEqual([
      { type: 'paragraph', children: [{ type: 'text', text: 'line one line two' }] },
      { type: 'paragraph', children: [{ type: 'text', text: 'second paragraph' }] },
    ])
  })

  it('parses fenced code blocks verbatim, without interpreting markup', () => {
    const blocks = parseMarkdown('```python\nx = "**a**"\n# not a heading\n```\nafter')
    expect(blocks[0]).toEqual({ type: 'code', text: 'x = "**a**"\n# not a heading' })
    expect(blocks[1]).toEqual({ type: 'paragraph', children: [{ type: 'text', text: 'after' }] })
  })

  it('treats an unclosed code fence as code until the end', () => {
    expect(parseMarkdown('```\nabc\ndef')).toEqual([{ type: 'code', text: 'abc\ndef' }])
  })

  it('parses unordered and ordered lists, joining indented continuation lines', () => {
    expect(parseMarkdown('- one\n- two\n  continued\n* three')).toEqual([
      {
        type: 'list',
        ordered: false,
        items: [
          [{ type: 'text', text: 'one' }],
          [{ type: 'text', text: 'two continued' }],
          [{ type: 'text', text: 'three' }],
        ],
      },
    ])
    const ordered = parseMarkdown('1. first\n2. second')[0]
    expect(ordered).toMatchObject({ type: 'list', ordered: true })
  })

  it('parses a table with a header, a separator row and body rows', () => {
    const [table] = parseMarkdown('| Pillow | status |\n|---|---|\n| 10.4.0 | safe |\n| **11.1.0** | **affected** |')
    expect(table).toMatchObject({ type: 'table' })
    if (table.type !== 'table') throw new Error('table expected')
    expect(table.header).toEqual([[{ type: 'text', text: 'Pillow' }], [{ type: 'text', text: 'status' }]])
    expect(table.rows.length).toBe(2)
    expect(table.rows[1][0]).toEqual([{ type: 'strong', children: [{ type: 'text', text: '11.1.0' }] }])
  })

  it('does not treat a line with a pipe but no separator row as a table', () => {
    expect(parseMarkdown('a | b')[0]).toMatchObject({ type: 'paragraph' })
  })

  it('parses a blockquote, and the markdown inside it', () => {
    expect(parseMarkdown('> **note**\n> text')).toEqual([
      {
        type: 'quote',
        blocks: [{
          type: 'paragraph',
          children: [
            { type: 'strong', children: [{ type: 'text', text: 'note' }] },
            { type: 'text', text: ' text' },
          ],
        }],
      },
    ])
  })

  it('parses a horizontal rule', () => {
    expect(parseMarkdown('above\n\n---\n\nbelow').map(b => b.type)).toEqual(['paragraph', 'rule', 'paragraph'])
  })

  it('starts a new block in the middle of a paragraph (a heading right after text)', () => {
    expect(parseMarkdown('text\n### Heading').map(b => b.type)).toEqual(['paragraph', 'heading'])
  })

  it('handles Windows line endings', () => {
    expect(parseMarkdown('# A\r\n\r\nB')).toHaveLength(2)
  })

  it('returns nothing for empty text, and always terminates on odd input', () => {
    expect(parseMarkdown('')).toEqual([])
    expect(parseMarkdown('|\n|\n---|\n> \n- \n```').length).toBeGreaterThan(0)
  })

  it('keeps a "#" in the middle of a heading (C#), and strips only the closing hashes', () => {
    expect(parseMarkdown('## C# notes ##')[0]).toEqual({
      type: 'heading', level: 2, children: [{ type: 'text', text: 'C# notes' }],
    })
    expect(parseMarkdown('# C#')[0]).toMatchObject({ children: [{ type: 'text', text: 'C#' }] })
    expect(parseMarkdown('###')[0]).toEqual({ type: 'heading', level: 3, children: [] })
    // 「#」の直後に空白が無ければ見出しではない（ハッシュタグ）
    expect(parseMarkdown('#hashtag')[0]).toMatchObject({ type: 'paragraph' })
  })

  it('accepts alignment colons in a table separator', () => {
    expect(parseMarkdown('| a | b |\n|:---|---:|\n| 1 | 2 |')[0]).toMatchObject({ type: 'table' })
  })
})

// 外部データのため、悪意ある入力でもブラウザが固まらないこと（ReDoS・入れ子・巨大入力の対策）
describe('hostile input', () => {
  // 時間の上限は、遅い実行環境でも誤検知しないよう余裕を持たせている（通常は数十ミリ秒以下）
  const LIMIT_MS = 1500
  const timed = (fn: () => unknown) => {
    const start = performance.now()
    fn()
    return performance.now() - start
  }

  const CASES: Record<string, string> = {
    'heading with a huge run of spaces': '#' + ' '.repeat(MAX_SOURCE_LENGTH),
    'heading with many hashes and spaces': '# ' + '# '.repeat(MAX_SOURCE_LENGTH / 2),
    'many unclosed link openers': '['.repeat(MAX_SOURCE_LENGTH),
    'many unclosed link texts': '[a'.repeat(MAX_SOURCE_LENGTH / 2),
    'link with a very long URL': '[a](' + 'x'.repeat(MAX_SOURCE_LENGTH),
    'many unclosed images': '!['.repeat(MAX_SOURCE_LENGTH / 2),
    'many backticks without a closer': '`a '.repeat(MAX_SOURCE_LENGTH / 3),
    'backtick runs of growing length': Array.from({ length: 150 }, (_, i) => '`'.repeat(i + 1) + 'x').join(' '),
    'many unclosed bold markers': '**a '.repeat(MAX_SOURCE_LENGTH / 4),
    'many unclosed italics': '*a '.repeat(MAX_SOURCE_LENGTH / 3),
    'many underscores': '_a'.repeat(MAX_SOURCE_LENGTH / 2),
    'deeply nested quotes': '> '.repeat(5000) + 'x',
    'deeply nested emphasis': '*_'.repeat(2000) + 'x' + '_*'.repeat(2000),
    'table separator lookalike': '|' + '---|'.repeat(MAX_SOURCE_LENGTH / 4),
    'horizontal rule lookalike': '- '.repeat(MAX_SOURCE_LENGTH / 2) + 'x',
    'a huge number of list items': '- a\n'.repeat(MAX_SOURCE_LENGTH / 4),
    'a huge number of lines': 'a\n'.repeat(MAX_SOURCE_LENGTH / 2),
    'a huge number of pipes': '|'.repeat(MAX_SOURCE_LENGTH),
  }

  for (const [name, input] of Object.entries(CASES)) {
    it(`parses quickly: ${name}`, () => {
      expect(timed(() => parseMarkdown(input))).toBeLessThan(LIMIT_MS)
    })
  }

  it('does not overflow the stack on deeply nested quotes or emphasis', () => {
    expect(() => parseMarkdown(CASES['deeply nested quotes'])).not.toThrow()
    expect(() => parseMarkdown(CASES['deeply nested emphasis'])).not.toThrow()
  })

  it('cuts text longer than the limit, and says that the rest was omitted', () => {
    const long = 'word '.repeat(MAX_SOURCE_LENGTH) // 上限の5倍
    const blocks = parseMarkdown(long)
    const last = blocks[blocks.length - 1]
    expect(JSON.stringify(last)).toContain('以降は省略しました')
    // 解析された文字数が、上限を大きく超えていない
    const parsed = JSON.stringify(blocks[0]).length
    expect(parsed).toBeLessThan(MAX_SOURCE_LENGTH * 2)
  })

  it('does not add the omission notice to text within the limit', () => {
    expect(JSON.stringify(parseMarkdown('a'.repeat(MAX_SOURCE_LENGTH)))).not.toContain('省略')
  })
})
