import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { JvnRow } from './JvnRow'
import type { JvnVulnerabilityOut } from '../../api/client'

const SEVERITY_CLS: Record<string, string> = {
  High: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
}

function makeItem(overrides: Partial<JvnVulnerabilityOut> = {}): JvnVulnerabilityOut {
  return {
    jvndb_id: 'JVNDB-2026-000001',
    title: 'Sample vulnerability title',
    overview: 'Overview of the vulnerability.',
    cve_ids: ['CVE-2026-0003'],
    severity: 'High',
    cvss_score: 7.2,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L',
    affected_products: [{ vendor: 'Acme', product: 'Widget', cpe: '' }],
    references: [],
    jvn_url: 'https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html',
    date_published: '2026-06-01T00:00:00Z',
    date_last_modified: '2026-06-02T00:00:00Z',
    ...overrides,
  }
}

function renderRow(item: JvnVulnerabilityOut) {
  return render(
    <table>
      <tbody>
        <JvnRow item={item} severityClassMap={SEVERITY_CLS} />
      </tbody>
    </table>,
  )
}

describe('JvnRow', () => {
  it('shows an em dash when there is no affected product', () => {
    renderRow(makeItem({ affected_products: [] }))
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it('shows a "+N products" marker when there is more than one affected product', () => {
    renderRow(makeItem({
      affected_products: [
        { vendor: 'Acme', product: 'Widget', cpe: '' },
        { vendor: 'Acme', product: 'Gadget', cpe: '' },
      ],
    }))
    expect(screen.getByText('+1 製品')).toBeInTheDocument()
  })

  it('expands to show the overview, CVSS vector, and full CVE list when clicked', () => {
    const item = makeItem()
    renderRow(item)
    expect(screen.queryByText(item.overview)).not.toBeInTheDocument()

    fireEvent.click(screen.getByText(item.title))
    expect(screen.getByText(item.overview)).toBeInTheDocument()
    expect(screen.getByText(item.cvss_vector!)).toBeInTheDocument()
    // 同じ CVE ID がヘッダー（代表表示）と展開後の全件表示の両方にリンクとして
    // 描画されるため、展開後は2箇所に増えることを確認する
    expect(screen.getAllByText(item.cve_ids[0])).toHaveLength(2)
  })

  it('does not toggle the row when clicking the JVNDB ID link itself', () => {
    const item = makeItem()
    renderRow(item)
    const link = screen.getByText(item.jvndb_id).closest('a')!
    fireEvent.click(link)
    expect(screen.queryByText(item.overview)).not.toBeInTheDocument()
  })

  it('does not toggle the row when clicking a related CVE link', () => {
    const item = makeItem({ cve_ids: ['CVE-2026-0003'] })
    renderRow(item)
    const cveLink = screen.getByText('CVE-2026-0003').closest('a')!
    fireEvent.click(cveLink)
    expect(screen.queryByText(item.overview)).not.toBeInTheDocument()
  })
})
