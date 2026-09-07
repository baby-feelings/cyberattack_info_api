import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { OsvRow } from './OsvRow'
import type { OsvVulnerabilityOut } from '../../api/client'

const SEVERITY_CLS: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
}

function makeItem(overrides: Partial<OsvVulnerabilityOut> = {}): OsvVulnerabilityOut {
  return {
    osv_id: 'GHSA-test-0001',
    ecosystem: 'PyPI',
    package_name: 'requests',
    aliases: ['CVE-2026-0002'],
    summary: 'A summary of the vulnerability.',
    details: 'Full details of the vulnerability.',
    severity: 'CRITICAL',
    cvss_score: 9.1,
    affected_versions: ['1.0.0'],
    fixed_versions: ['1.0.1'],
    references: ['https://example.com/advisory'],
    published: '2026-06-01T00:00:00Z',
    modified: '2026-06-02T00:00:00Z',
    ...overrides,
  }
}

function renderRow(item: OsvVulnerabilityOut) {
  return render(
    <table>
      <tbody>
        <OsvRow item={item} severityClassMap={SEVERITY_CLS} />
      </tbody>
    </table>,
  )
}

describe('OsvRow', () => {
  it('shows the CVSS score alongside the severity badge', () => {
    renderRow(makeItem({ cvss_score: 9.1 }))
    expect(screen.getByText('9.1')).toBeInTheDocument()
  })

  it('falls back to a generic ecosystem badge style for an unmapped ecosystem', () => {
    renderRow(makeItem({ ecosystem: 'UnknownEco' }))
    expect(screen.getByText('UnknownEco')).toBeInTheDocument()
  })

  it('expands to show details, fixed versions, aliases, and references when clicked', () => {
    // 非 CVE のエイリアスを使い、ヘッダーの CVE エイリアスリンクと展開後の
    // エイリアス全件表示が同じテキストを重複描画しないようにする
    const item = makeItem({ aliases: ['OSV-INTERNAL-001'] })
    renderRow(item)
    expect(screen.queryByText(item.details!)).not.toBeInTheDocument()

    fireEvent.click(screen.getByText(item.package_name))
    expect(screen.getByText(item.details!)).toBeInTheDocument()
    expect(screen.getByText(item.fixed_versions[0])).toBeInTheDocument()
    expect(screen.getByText('OSV-INTERNAL-001')).toBeInTheDocument()
    expect(screen.getByText(item.references[0])).toBeInTheDocument()
  })

  it('does not toggle the row when clicking the OSV ID link itself', () => {
    const item = makeItem()
    renderRow(item)
    const link = screen.getByText(item.osv_id).closest('a')!
    fireEvent.click(link)
    expect(screen.queryByText(item.details!)).not.toBeInTheDocument()
  })

  it('does not toggle the row when clicking a CVE alias link', () => {
    const item = makeItem({ aliases: ['CVE-2026-0002'] })
    renderRow(item)
    const cveLink = screen.getByText('CVE-2026-0002').closest('a')!
    fireEvent.click(cveLink)
    expect(screen.queryByText(item.details!)).not.toBeInTheDocument()
  })
})
