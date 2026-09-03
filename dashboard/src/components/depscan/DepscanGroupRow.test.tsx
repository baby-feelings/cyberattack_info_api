import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { DepscanGroupRow } from './DepscanGroupRow'
import { groupFindings, type FindingGroup } from './grouping'
import type { DependencyFindingOut } from '../../api/client'

function makeFinding(overrides: Partial<DependencyFindingOut> = {}): DependencyFindingOut {
  return {
    repo_full_name: 'baby-feelings/baby_grow',
    ecosystem: 'PyPI',
    package_name: 'cryptography',
    installed_version: '3.4.7',
    osv_id: 'GHSA-test-0001',
    severity: 'HIGH',
    cvss_score: 7.5,
    summary: 'Test vulnerability',
    fixed_versions: ['3.4.8'],
    manifest_path: 'requirements.txt',
    detected_at: '2026-06-01T00:00:00Z',
    resolved_at: null,
    ...overrides,
  }
}

function makeGroup(findings: DependencyFindingOut[]): FindingGroup {
  return groupFindings(findings)[0]
}

function renderRow(group: FindingGroup) {
  return render(
    <table>
      <tbody>
        <DepscanGroupRow group={group} />
      </tbody>
    </table>,
  )
}

describe('DepscanGroupRow', () => {
  it('shows the repo, package, and total finding count collapsed by default', () => {
    const group = makeGroup([makeFinding({ osv_id: 'GHSA-1' }), makeFinding({ osv_id: 'GHSA-2' })])
    renderRow(group)
    expect(screen.getByText('baby-feelings/baby_grow')).toBeInTheDocument()
    expect(screen.getByText('cryptography')).toBeInTheDocument()
    expect(screen.getByText('計2件')).toBeInTheDocument()
    expect(screen.queryByText(/ロックファイル/)).not.toBeInTheDocument()
  })

  it('shows a "resolved" marker only when every finding in the group is resolved', () => {
    const resolvedGroup = makeGroup([makeFinding({ resolved_at: '2026-06-02T00:00:00Z' })])
    const { rerender } = renderRow(resolvedGroup)
    expect(screen.getByText('解決済み')).toBeInTheDocument()

    const openGroup = makeGroup([makeFinding({ resolved_at: null })])
    rerender(
      <table>
        <tbody>
          <DepscanGroupRow group={openGroup} />
        </tbody>
      </table>,
    )
    expect(screen.queryByText('解決済み')).not.toBeInTheDocument()
  })

  it('shows "未提供" when no fixed version is available', () => {
    const group = makeGroup([makeFinding({ fixed_versions: [] })])
    renderRow(group)
    expect(screen.getByText('未提供')).toBeInTheDocument()
  })

  it('expands to show per-CVE details when the row is clicked', () => {
    const group = makeGroup([
      makeFinding({ osv_id: 'GHSA-1', summary: 'First vuln summary' }),
    ])
    renderRow(group)
    expect(screen.queryByText('First vuln summary')).not.toBeInTheDocument()

    // 展開トリガーは行全体だが、リポジトリリンク自体は stopPropagation されるため
    // パッケージ名セルなどリンク外の要素をクリックする
    fireEvent.click(screen.getByText('cryptography'))
    expect(screen.getByText('First vuln summary')).toBeInTheDocument()
    expect(screen.getByText('GHSA-1')).toBeInTheDocument()
  })

  it('sorts expanded CVE entries by severity (most severe first)', () => {
    const group = makeGroup([
      makeFinding({ osv_id: 'GHSA-low', severity: 'LOW' }),
      makeFinding({ osv_id: 'GHSA-critical', severity: 'CRITICAL' }),
    ])
    renderRow(group)
    fireEvent.click(screen.getByText('cryptography'))
    const ids = screen.getAllByText(/^GHSA-(low|critical)$/).map(el => el.textContent)
    expect(ids).toEqual(['GHSA-critical', 'GHSA-low'])
  })

  it('does not toggle the row when clicking the repo link itself', () => {
    const group = makeGroup([makeFinding()])
    renderRow(group)
    const link = screen.getByText('baby-feelings/baby_grow').closest('a')!
    fireEvent.click(link)
    // stopPropagation on the link's onClick means the row's own toggle handler never fires
    expect(screen.queryByText(/ロックファイル/)).not.toBeInTheDocument()
  })
})
