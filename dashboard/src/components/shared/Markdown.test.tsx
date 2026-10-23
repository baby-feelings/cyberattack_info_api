import { describe, it, expect } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { Markdown } from './Markdown'

// OSV の実際の詳細（GitHub Advisory）に近い文章
const ADVISORY = `### Summary

Every Pillow wheel from 11.1.0 onward bundles a vulnerable
OpenJPEG. See \`im.load()\` and **never** ignore it.

### Details

## Affected wheels

| Pillow | bundled OpenJPEG | status |
|---|---|---|
| 10.4.0 | 2.5.2 | safe |
| **11.1.0** | **2.5.3** | **affected** |

- upgrade to [13.0.0](https://example.com/pillow)
- or pin \`openjpeg\`

\`\`\`
pip install "pillow>=13.0.0"
\`\`\`
`

describe('Markdown', () => {
  it('shows headings as headings, without the "###" marks', () => {
    render(<Markdown source={ADVISORY} />)
    expect(screen.getByRole('heading', { name: 'Summary' })).toHaveAttribute('aria-level', '3')
    expect(screen.getByRole('heading', { name: 'Affected wheels' })).toHaveAttribute('aria-level', '2')
    expect(document.body.textContent).not.toContain('###')
    expect(document.body.textContent).not.toContain('**')
  })

  it('shows a table as a table', () => {
    render(<Markdown source={ADVISORY} />)
    const table = screen.getByRole('table')
    expect(within(table).getAllByRole('columnheader').map(h => h.textContent)).toEqual([
      'Pillow', 'bundled OpenJPEG', 'status',
    ])
    expect(within(table).getAllByRole('row')).toHaveLength(3)
    expect(within(table).getByText('affected').tagName).toBe('STRONG')
  })

  it('shows inline code, bold, lists and code blocks', () => {
    render(<Markdown source={ADVISORY} />)
    expect(screen.getByText('im.load()').tagName).toBe('CODE')
    expect(screen.getByText('never').tagName).toBe('STRONG')
    expect(screen.getAllByRole('listitem')).toHaveLength(2)
    expect(screen.getByText(/pip install/).tagName).toBe('PRE')
  })

  it('opens http(s) links in a new tab without leaking the opener', () => {
    render(<Markdown source={ADVISORY} />)
    const link = screen.getByRole('link', { name: '13.0.0' })
    expect(link).toHaveAttribute('href', 'https://example.com/pillow')
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })

  describe('XSS: untrusted text is never turned into markup', () => {
    it('shows script tags and event handlers as plain text', () => {
      const { container } = render(<Markdown source={'<script>alert(1)</script> <img src=x onerror=alert(1)>'} />)
      expect(container.querySelector('script')).toBeNull()
      expect(container.querySelector('img')).toBeNull()
      expect(container.textContent).toContain('<script>alert(1)</script>')
    })

    it('does not make links of javascript: URLs', () => {
      const { container } = render(<Markdown source="[click me](javascript:alert(1))" />)
      expect(container.querySelector('a')).toBeNull()
      expect(container.textContent).toContain('click me')
    })

    it('does not load images', () => {
      const { container } = render(<Markdown source="![tracker](https://evil.example/pixel.png)" />)
      expect(container.querySelector('img')).toBeNull()
    })
  })

  it('renders nothing visible for empty text', () => {
    const { container } = render(<Markdown source="" />)
    expect(container.textContent).toBe('')
  })
})
