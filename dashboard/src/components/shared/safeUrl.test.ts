import { describe, it, expect } from 'vitest'
import { safeHttpUrl } from './safeUrl'

describe('safeHttpUrl', () => {
  it('allows http and https URLs as they are', () => {
    expect(safeHttpUrl('https://nvd.nist.gov/vuln/detail/CVE-2024-0001'))
      .toBe('https://nvd.nist.gov/vuln/detail/CVE-2024-0001')
    expect(safeHttpUrl('http://example.com/a?b=c#d')).toBe('http://example.com/a?b=c#d')
  })

  it.each([
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    ' javascript:alert(1)',
    'java\tscript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    'file:///etc/passwd',
    'ftp://example.com/x',
  ])('rejects non-http(s) scheme: %s', url => {
    expect(safeHttpUrl(url)).toBeUndefined()
  })

  it('rejects relative URLs, garbage, empty, null and undefined', () => {
    expect(safeHttpUrl('/relative/path')).toBeUndefined()
    expect(safeHttpUrl('not a url')).toBeUndefined()
    expect(safeHttpUrl('')).toBeUndefined()
    expect(safeHttpUrl(null)).toBeUndefined()
    expect(safeHttpUrl(undefined)).toBeUndefined()
  })
})
