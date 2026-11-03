import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DepscanPanel } from './DepscanPanel'
import {
  fetchAllDepscanFindings, fetchDepscanStats, fetchCrawlerLogs,
  type DependencyFindingOut,
} from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    fetchAllDepscanFindings: vi.fn(), fetchDepscanStats: vi.fn(), fetchCrawlerLogs: vi.fn(),
  }
})

function finding(pkg: string, severity: string, detectedAt: string): DependencyFindingOut {
  return {
    repo_full_name: 'baby-feelings/baby_grow', ecosystem: 'PyPI', package_name: pkg,
    installed_version: '1.0.0', osv_id: `GHSA-${pkg}`, severity, cvss_score: 5, summary: 's',
    fixed_versions: [], manifest_path: 'requirements.txt', detected_at: detectedAt, resolved_at: null,
    reachability: null, repo_visibility: null, is_malicious: false, priority_reasons: [],
  }
}

// 重要度順: high-old(HIGH) → low-new(LOW)。検知日順: low-new（新）→ high-old（旧）
const FINDINGS = [
  finding('low-new', 'LOW', '2026-06-15T03:00:00Z'),
  finding('high-old', 'HIGH', '2026-06-01T03:00:00Z'),
]

function packageOrder(): string[] {
  const table = screen.getByRole('table', { name: '依存ライブラリ脆弱性一覧' })
  return ['low-new', 'high-old']
    .filter(p => within(table).queryByText(p))
    .sort((a, b) => (
      within(table).getByText(a).compareDocumentPosition(within(table).getByText(b))
      & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1
    ))
}

describe('DepscanPanel date dividers', () => {
  beforeEach(() => {
    vi.mocked(fetchAllDepscanFindings).mockResolvedValue(FINDINGS)
    vi.mocked(fetchDepscanStats).mockResolvedValue({ total: 2, repos: [], severities: [] })
    vi.mocked(fetchCrawlerLogs).mockResolvedValue([])
  })
  afterEach(() => vi.resetAllMocks())

  it('sorts by severity without dividers by default, and by detected day with dividers on request', async () => {
    const user = userEvent.setup()
    render(<DepscanPanel />)

    await waitFor(() => expect(screen.getByText('high-old')).toBeInTheDocument())
    expect(packageOrder()).toEqual(['high-old', 'low-new'])
    expect(screen.queryAllByRole('row', { name: /の区切り$/ })).toHaveLength(0)

    await user.click(screen.getByRole('button', { name: '検知日' }))
    await waitFor(() => expect(screen.getAllByRole('row', { name: /の区切り$/ })).toHaveLength(2))
    expect(packageOrder()).toEqual(['low-new', 'high-old'])
    expect(screen.getByRole('row', { name: '2026年6月15日の区切り' })).toBeInTheDocument()
  })
})
