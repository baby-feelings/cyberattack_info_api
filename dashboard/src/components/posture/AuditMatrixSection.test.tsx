import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AuditMatrixSection } from './AuditMatrixSection'
import { AUDIT_STATUS_VIEW, POSTURE_TEXT } from './postureConfig'
import { AuditMatrix } from './model/AuditMatrix'
import { auditMatrix, failed, loading, ready, unauthorized } from './testFixtures'

// 最終取得は、API（クローラーのログ）を読むため、ここでは、描かない
vi.mock('../freshness/LastFetched', () => ({ LastFetched: () => null }))

const table = () => screen.getByRole('table', { name: POSTURE_TEXT.audit.title })

describe('AuditMatrixSection', () => {
  it('takes the column headings from the check labels the API returned', () => {
    render(<AuditMatrixSection source={ready(auditMatrix())} onRetry={vi.fn()} />)
    const headers = within(table()).getAllByRole('columnheader').map((h) => h.textContent)
    expect(headers).toEqual([
      POSTURE_TEXT.audit.repoColumn, 'シークレットスキャン', 'push 保護', 'ブランチ保護',
    ])
  })

  it('names every cell with the repository, the check and the state, and shows a glyph as well as a colour', () => {
    render(<AuditMatrixSection source={ready(auditMatrix())} onRetry={vi.fn()} />)
    // 既定は「改善が必要なものだけ」なので、不合格のある beta だけが出る
    const failedCell = screen.getByRole('button', {
      name: `owner/beta シークレットスキャン ${AUDIT_STATUS_VIEW.ng.label}`,
    })
    expect(failedCell).toHaveTextContent(AUDIT_STATUS_VIEW.ng.glyph)
  })

  it('shows a check the repository does not have as unavailable, not as a button', async () => {
    const user = userEvent.setup()
    render(<AuditMatrixSection source={ready(auditMatrix())} onRetry={vi.fn()} />)
    await user.click(screen.getByRole('checkbox', { name: POSTURE_TEXT.audit.onlyIssues }))   // 全リポジトリを出す

    const missing = screen.getByLabelText(`owner/alpha ブランチ保護 ${AUDIT_STATUS_VIEW.unavailable.label}`)
    expect(missing).toHaveTextContent(AUDIT_STATUS_VIEW.unavailable.glyph)
    expect(missing.tagName).not.toBe('BUTTON')
  })

  it('opens the detail and the fix on the spot when a cell is pressed, and closes it when pressed again', async () => {
    const user = userEvent.setup()
    render(<AuditMatrixSection source={ready(auditMatrix())} onRetry={vi.fn()} />)
    const cell = screen.getByRole('button', { name: /owner\/beta シークレットスキャン/ })

    await user.click(cell)
    expect(cell).toHaveAttribute('aria-expanded', 'true')
    const detail = screen.getByRole('region', { name: /owner\/beta.*シークレットスキャン/ })
    expect(detail).toHaveTextContent('無効になっています')
    expect(detail).toHaveTextContent('設定の「セキュリティ」で有効にする')

    await user.click(cell)
    expect(screen.queryByRole('region', { name: /owner\/beta.*シークレットスキャン/ })).not.toBeInTheDocument()
  })

  it('shows only the repositories with issues by default, and every repository when the box is cleared', async () => {
    const user = userEvent.setup()
    render(<AuditMatrixSection source={ready(auditMatrix())} onRetry={vi.fn()} />)
    expect(within(table()).queryByText('owner/alpha')).not.toBeInTheDocument()
    expect(within(table()).getByText('owner/beta')).toBeInTheDocument()

    await user.click(screen.getByRole('checkbox', { name: POSTURE_TEXT.audit.onlyIssues }))
    expect(within(table()).getByText('owner/alpha')).toBeInTheDocument()
  })

  it('searches the repository name', async () => {
    const user = userEvent.setup()
    render(<AuditMatrixSection source={ready(auditMatrix())} onRetry={vi.fn()} />)
    await user.click(screen.getByRole('checkbox', { name: POSTURE_TEXT.audit.onlyIssues }))

    await user.type(screen.getByRole('searchbox', { name: POSTURE_TEXT.audit.search }), 'ALPHA')

    expect(within(table()).getByText('owner/alpha')).toBeInTheDocument()
    expect(within(table()).queryByText('owner/beta')).not.toBeInTheDocument()
  })

  it('tells the user what to do when there is no audit result at all', () => {
    render(<AuditMatrixSection source={ready(new AuditMatrix([]))} onRetry={vi.fn()} />)
    expect(screen.getByText(POSTURE_TEXT.audit.empty)).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('says so when every repository passes', async () => {
    const user = userEvent.setup()
    const allGood = auditMatrix().rows({ query: 'alpha' })
    render(<AuditMatrixSection source={ready(new AuditMatrix(allGood))} onRetry={vi.fn()} />)
    // 既定の「改善が必要なものだけ」で、不合格がなければ、その旨を出す（表は、出さない）
    expect(screen.getByText(POSTURE_TEXT.audit.noIssues)).toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: POSTURE_TEXT.audit.onlyIssues }))
    expect(within(table()).getByText('owner/alpha')).toBeInTheDocument()
  })

  it('shows a message from the config and a retry button when loading failed, without the raw error text', async () => {
    const user = userEvent.setup()
    const onRetry = vi.fn()
    render(<AuditMatrixSection source={failed('API error 500: /api/repo-audit')} onRetry={onRetry} />)

    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent(POSTURE_TEXT.loadFailed)
    expect(alert).not.toHaveTextContent('API error')           // 内部のパスを、画面に出さない
    expect(alert).toHaveAttribute('title', 'API error 500: /api/repo-audit')   // 詳細は、ホバーで読める
    await user.click(screen.getByRole('button', { name: POSTURE_TEXT.retry }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('asks to log in again, with no retry button, when the session is invalid or expired', () => {
    render(<AuditMatrixSection source={unauthorized()} onRetry={vi.fn()} />)

    expect(screen.getByRole('alert')).toHaveTextContent(POSTURE_TEXT.sessionExpired)
    expect(screen.getByRole('link', { name: POSTURE_TEXT.relogin })).toHaveAttribute('href')
    // 同じ（無効な）トークンで、再試行しても、必ず失敗するため、再試行は出さない
    expect(screen.queryByRole('button', { name: POSTURE_TEXT.retry })).not.toBeInTheDocument()
  })

  it('shows a loading state', () => {
    render(<AuditMatrixSection source={loading()} onRetry={vi.fn()} />)
    expect(screen.getByRole('status', { name: POSTURE_TEXT.loading })).toBeInTheDocument()
  })
})
