import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { KevRow } from './KevRow'
import type { VulnerabilityOut } from '../../api/client'

function makeItem(overrides: Partial<VulnerabilityOut> = {}): VulnerabilityOut {
  return {
    cve_id: 'CVE-2026-0001',
    vendor_project: 'Acme',
    product: 'Widget',
    vulnerability_name: 'Remote Code Execution',
    description: 'Detailed description of the vulnerability.',
    required_action: null,
    date_added: '2026-06-01',
    epss_score: null,
    epss_percentile: null,
    epss_updated_at: null,
    ...overrides,
  }
}

function renderRow(item: VulnerabilityOut) {
  return render(
    <table>
      <tbody>
        <KevRow item={item} />
      </tbody>
    </table>,
  )
}

describe('KevRow', () => {
  it('shows an em dash when the EPSS score is unavailable', () => {
    renderRow(makeItem({ epss_score: null }))
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it.each([
    [0.8, '80.0%'],
    [0.2, '20.0%'],
    [0.05, '5.0%'],
    [0.001, '0.1%'],
  ])('renders the EPSS score %s as %s across every color bracket', (score, expected) => {
    renderRow(makeItem({ epss_score: score }))
    expect(screen.getByText(expected)).toBeInTheDocument()
  })

  it('expands to show the description and required action when the row is clicked', () => {
    const item = makeItem({ required_action: 'Apply the vendor patch immediately.' })
    renderRow(item)
    expect(screen.queryByText(item.description)).not.toBeInTheDocument()

    fireEvent.click(screen.getByText(item.product))
    expect(screen.getByText(item.description)).toBeInTheDocument()
    expect(screen.getByText('Apply the vendor patch immediately.')).toBeInTheDocument()
  })

  it('shows the EPSS percentile and update date when expanded with a score present', () => {
    const item = makeItem({
      epss_score: 0.42, epss_percentile: 0.9, epss_updated_at: '2026-06-05T00:00:00Z',
    })
    renderRow(item)
    fireEvent.click(screen.getByText(item.product))
    expect(screen.getByText(/パーセンタイル 90.0%/)).toBeInTheDocument()
    expect(screen.getByText(/更新:/)).toBeInTheDocument()
  })

  it('does not toggle the row when clicking the CVE link itself', () => {
    const item = makeItem()
    renderRow(item)
    const link = screen.getByText(item.cve_id).closest('a')!
    fireEvent.click(link)
    // stopPropagation on the link's onClick means the row's own toggle handler never fires
    expect(screen.queryByText(item.description)).not.toBeInTheDocument()
  })
})
