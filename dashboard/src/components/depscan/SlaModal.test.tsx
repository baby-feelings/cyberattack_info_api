import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SlaModal } from './SlaModal'
import { fetchSlaReport, type SlaReport } from '../../api/client'

vi.mock('../../api/client', async () => {
  const actual = await vi.importActual<typeof import('../../api/client')>('../../api/client')
  return { ...actual, fetchSlaReport: vi.fn() }
})

const mockedFetch = vi.mocked(fetchSlaReport)

function report(overrides: Partial<SlaReport> = {}): SlaReport {
  return {
    generated_at: '2026-11-02T00:00:00+00:00',
    mttr_window_days: 90,
    policy: { critical_days: 7, high_days: 30, medium_days: 90, kev_days: 7, excluded_osv_ids: [] },
    summary: { open_with_deadline: 3, overdue: 2, resolved: 4, mttr_days: 12.5 },
    by_severity: [
      { severity: 'CRITICAL', deadline_days: 7, open: 1, overdue: 1, resolved: 0, mttr_days: null },
      { severity: 'HIGH', deadline_days: 30, open: 2, overdue: 1, resolved: 4, mttr_days: 12.5 },
      { severity: 'LOW', deadline_days: null, open: 1, overdue: 0, resolved: 0, mttr_days: null },
    ],
    by_repo: [
      { repo_full_name: 'baby-feelings/app-one', open: 2, overdue: 2, resolved: 4, mttr_days: 12.5 },
      { repo_full_name: 'baby-feelings/app-two', open: 1, overdue: 0, resolved: 0, mttr_days: null },
    ],
    overdue: [
      {
        repo_full_name: 'baby-feelings/app-one', package_name: 'lodash', installed_version: '4.17.15',
        osv_id: 'GHSA-lodash-1', severity: 'CRITICAL', is_kev: true, is_malicious: false,
        detected_at: '2026-10-01T00:00:00+00:00', deadline_days: 7,
        due_at: '2026-10-08T00:00:00+00:00', overdue_days: 25,
      },
      {
        repo_full_name: 'baby-feelings/app-one', package_name: 'evil-pkg', installed_version: '1.0.0',
        osv_id: 'MAL-2026-1', severity: 'CRITICAL', is_kev: false, is_malicious: true,
        detected_at: '2026-10-20T00:00:00+00:00', deadline_days: 7,
        due_at: '2026-10-27T00:00:00+00:00', overdue_days: 6,
      },
    ],
    ...overrides,
  }
}

async function openDialog() {
  render(<SlaModal open onClose={vi.fn()} authToken="tok" />)
  await waitFor(() => expect(screen.getByLabelText('対応状況の概要')).toBeInTheDocument())
}

describe('SlaModal', () => {
  // 波括弧で包む（モック関数を返すと、Vitest が後始末の関数として呼び出してしまう）
  beforeEach(() => { mockedFetch.mockResolvedValue(report()) })
  afterEach(() => { vi.clearAllMocks() })

  it('renders nothing and fetches nothing while closed', () => {
    render(<SlaModal open={false} onClose={vi.fn()} />)

    expect(screen.queryByRole('dialog', { name: '対応状況' })).not.toBeInTheDocument()
    expect(mockedFetch).not.toHaveBeenCalled()
  })

  it('fetches the active apps first, with the session token', async () => {
    await openDialog()

    expect(mockedFetch).toHaveBeenCalledWith('tok', 'active')
  })

  it('shows the summary tiles: overdue, open, resolved and MTTR', async () => {
    await openDialog()
    const tiles = screen.getByLabelText('対応状況の概要')

    expect(within(tiles).getByText('2 件')).toBeInTheDocument() // 期限超過
    expect(within(tiles).getByText('3 件')).toBeInTheDocument() // 未解決（期限あり）
    expect(within(tiles).getByText('4 件')).toBeInTheDocument() // 解決
    expect(within(tiles).getByText('12.5 日')).toBeInTheDocument()
    expect(within(tiles).getByText('直近90日の解決')).toBeInTheDocument()
  })

  it('shows the policy line', async () => {
    await openDialog()

    expect(screen.getByLabelText('対応期限')).toHaveTextContent(
      '対応期限: CRITICAL 7日 / HIGH 30日 / MEDIUM 90日 / KEV掲載 7日',
    )
  })

  it('mentions how many findings are excluded when some are', async () => {
    mockedFetch.mockResolvedValue(report({
      policy: { critical_days: 7, high_days: 30, medium_days: 90, kev_days: 7, excluded_osv_ids: ['GHSA-a', 'GHSA-b'] },
    }))
    await openDialog()

    expect(screen.getByLabelText('対応期限')).toHaveTextContent('除外中: 2件')
  })

  it('lists overdue findings with days overdue, KEV and malicious marks', async () => {
    await openDialog()
    const table = screen.getByRole('table', { name: '期限超過の検知一覧' })
    const rows = within(table).getAllByRole('row')

    expect(rows).toHaveLength(3) // ヘッダー + 2件
    expect(rows[1]).toHaveTextContent('lodash')
    expect(rows[1]).toHaveTextContent('25 日超過')
    expect(rows[1]).toHaveTextContent('KEV')
    expect(rows[2]).toHaveTextContent('evil-pkg')
    expect(within(rows[2]).getByTitle('悪意あるパッケージ')).toBeInTheDocument()
  })

  it('shows per-severity and per-repo tables, with a dash for no deadline / no MTTR', async () => {
    await openDialog()
    const bySeverity = screen.getByRole('table', { name: '重要度別の対応状況' })
    const low = within(bySeverity).getByRole('row', { name: /LOW/ })

    expect(within(bySeverity).getByRole('row', { name: /CRITICAL/ })).toHaveTextContent('7 日')
    expect(low).toHaveTextContent('—') // 期限なし
    const byRepo = screen.getByRole('table', { name: 'リポジトリ別の対応状況' })
    expect(within(byRepo).getByText('baby-feelings/app-one')).toBeInTheDocument()
  })

  it('shows a calm empty state when nothing is overdue', async () => {
    mockedFetch.mockResolvedValue(report({
      overdue: [],
      summary: { open_with_deadline: 1, overdue: 0, resolved: 0, mttr_days: null },
    }))
    await openDialog()

    expect(screen.getByText('期限を超えている検知はありません')).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: '期限超過の検知一覧' })).not.toBeInTheDocument()
    // 解決が無ければ平均対応日数は「—」
    expect(within(screen.getByLabelText('対応状況の概要')).getByText('—')).toBeInTheDocument()
  })

  it('refetches when the operating filter changes', async () => {
    const user = userEvent.setup()
    await openDialog()

    await user.click(screen.getByRole('button', { name: /運用停止中/ }))

    await waitFor(() => expect(mockedFetch).toHaveBeenLastCalledWith('tok', 'inactive'))
  })

  it('shows an error message when the fetch fails', async () => {
    mockedFetch.mockRejectedValue(new Error('boom'))
    render(<SlaModal open onClose={vi.fn()} />)

    expect(await screen.findByText('取得に失敗しました。時間をおいて再度お試しください')).toBeInTheDocument()
  })

  it('closes with the close button and the Escape key', async () => {
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(<SlaModal open onClose={onClose} />)
    await screen.findByLabelText('対応状況の概要')

    await user.click(screen.getByRole('button', { name: '閉じる' }))
    await user.keyboard('{Escape}')

    expect(onClose).toHaveBeenCalledTimes(2)
  })
})
