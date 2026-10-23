import { describe, it, expect } from 'vitest'
import { parseInline, parseMarkdown } from './parseMarkdown'

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
})
