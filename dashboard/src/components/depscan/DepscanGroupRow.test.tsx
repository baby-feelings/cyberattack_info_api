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
    reachability: null,
    repo_visibility: null,
    is_malicious: false,
    priority_reasons: [],
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

  it('shows a reachability badge reflecting the group\'s status', () => {
    const reachable = makeGroup([makeFinding({ reachability: 'reachable' })])
    const { rerender } = renderRow(reachable)
    expect(screen.getByText('到達可能')).toBeInTheDocument()

    const unreachable = makeGroup([makeFinding({ reachability: 'unreachable' })])
    rerender(
      <table>
        <tbody>
          <DepscanGroupRow group={unreachable} />
        </tbody>
      </table>,
    )
    expect(screen.getByText('未使用の可能性')).toBeInTheDocument()
  })

  it('falls back to "不明" when reachability is null', () => {
    const group = makeGroup([makeFinding({ reachability: null })])
    renderRow(group)
    expect(screen.getByText('不明')).toBeInTheDocument()
  })

  it('shows a Public badge when repo_visibility is public', () => {
    const group = makeGroup([makeFinding({ repo_visibility: 'public' })])
    renderRow(group)
    expect(screen.getByText('Public')).toBeInTheDocument()
  })

  it('shows a Private badge when repo_visibility is private', () => {
    const group = makeGroup([makeFinding({ repo_visibility: 'private' })])
    renderRow(group)
    expect(screen.getByText('Private')).toBeInTheDocument()
  })

  it('shows no visibility badge when repo_visibility is null', () => {
    const group = makeGroup([makeFinding({ repo_visibility: null })])
    renderRow(group)
    expect(screen.queryByText('Public')).not.toBeInTheDocument()
    expect(screen.queryByText('Private')).not.toBeInTheDocument()
  })

  it('shows a KEV badge when any finding in the group has kev_listed', () => {
    const group = makeGroup([
      makeFinding({ osv_id: 'GHSA-a', priority_reasons: [] }),
      makeFinding({ osv_id: 'GHSA-b', priority_reasons: ['kev_listed'] }),
    ])
    renderRow(group)
    expect(screen.getByText('KEV')).toBeInTheDocument()
  })

  it('shows no KEV badge when no finding has kev_listed', () => {
    const group = makeGroup([makeFinding({ priority_reasons: ['reachable'] })])
    renderRow(group)
    expect(screen.queryByText('KEV')).not.toBeInTheDocument()
  })

  it('shows a malicious-package badge when any finding in the group is malicious', () => {
    const group = makeGroup([
      makeFinding({ osv_id: 'GHSA-a' }),
      makeFinding({ osv_id: 'MAL-2026-1', is_malicious: true, priority_reasons: ['malicious_package'] }),
    ])
    renderRow(group)
    const badge = screen.getByText('🛑 悪意あり')
    expect(badge).toBeInTheDocument()
    // 脆弱性ではなくマルウェアで、対応が「削除」であることをツールチップで示す
    expect(badge).toHaveAttribute('title', expect.stringContaining('削除'))
  })

  it('shows no malicious-package badge for ordinary vulnerabilities', () => {
    renderRow(makeGroup([makeFinding()]))
    expect(screen.queryByText('🛑 悪意あり')).not.toBeInTheDocument()
  })

  it('labels the malicious_package reason when expanded', () => {
    const group = makeGroup([
      makeFinding({ is_malicious: true, priority_reasons: ['malicious_package'] }),
    ])
    renderRow(group)
    fireEvent.click(screen.getByText('cryptography'))
    expect(screen.getByText('悪意あるパッケージ')).toBeInTheDocument()
  })

  it('shows priority reason badges for each finding when expanded', () => {
    const group = makeGroup([
      makeFinding({ priority_reasons: ['kev_listed', 'epss_high', 'production_asset'] }),
    ])
    renderRow(group)
    fireEvent.click(screen.getByText('cryptography'))
    expect(screen.getByText('KEV掲載')).toBeInTheDocument()
    expect(screen.getByText('EPSS高')).toBeInTheDocument()
    expect(screen.getByText('本番資産')).toBeInTheDocument()
  })

  it('does not toggle the row when clicking the repo link itself', () => {
    const group = makeGroup([makeFinding()])
    renderRow(group)
    const link = screen.getByText('baby-feelings/baby_grow').closest('a')!
    fireEvent.click(link)
    // stopPropagation on the link's onClick means the row's own toggle handler never fires
    expect(screen.queryByText(/ロックファイル/)).not.toBeInTheDocument()
  })

  describe('exceptions (Issue #403)', () => {
    const EXCEPTION = {
      id: 3, status: 'accepted' as const, reason: '修正版が無い',
      expires_at: '2026-12-31T00:00:00Z', approver: 'alice',
    }

    it('tags a group whose every finding has an exception', () => {
      renderRow(makeGroup([
        makeFinding({ osv_id: 'GHSA-1', exception: EXCEPTION }),
        makeFinding({ osv_id: 'GHSA-2', exception: EXCEPTION }),
      ]))
      expect(screen.getByText('受容')).toBeInTheDocument()
    })

    it('does not tag a group with a finding that still needs action', () => {
      renderRow(makeGroup([
        makeFinding({ osv_id: 'GHSA-1', exception: EXCEPTION }),
        makeFinding({ osv_id: 'GHSA-2' }),
      ]))
      expect(screen.queryByText('受容')).not.toBeInTheDocument()
    })

    it('offers to register an exception per finding when logged in', () => {
      render(
        <table><tbody>
          <DepscanGroupRow
            group={makeGroup([makeFinding({ exception_key: 'PyPI|cryptography|GHSA-test-0001' })])}
            authToken="tok"
          />
        </tbody></table>,
      )
      fireEvent.click(screen.getByText('cryptography'))
      expect(screen.getByRole('button', { name: '例外にする' })).toBeInTheDocument()
    })

    it('shows the exception details when expanded', () => {
      render(
        <table><tbody>
          <DepscanGroupRow
            group={makeGroup([makeFinding({ exception_key: 'k', exception: EXCEPTION })])}
            authToken="tok"
          />
        </tbody></table>,
      )
      fireEvent.click(screen.getByText('cryptography'))
      expect(screen.getByText('理由: 修正版が無い')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: '解除' })).toBeInTheDocument()
    })

    it('has no exception controls for a finding without a key', () => {
      renderRow(makeGroup([makeFinding()]))
      fireEvent.click(screen.getByText('cryptography'))
      expect(screen.queryByRole('button', { name: '例外にする' })).not.toBeInTheDocument()
    })
  })
})
