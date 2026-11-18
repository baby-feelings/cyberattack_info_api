import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AlertList } from './model/AlertList'
import { AlertsSection } from './AlertsSection'
import { ALERT_KIND_VIEW, POSTURE_TEXT } from './postureConfig'
import { alertList, failed, loading, ready } from './testFixtures'

vi.mock('../freshness/LastFetched', () => ({ LastFetched: () => null }))

const table = () => screen.getByRole('table', { name: POSTURE_TEXT.alerts.title })
const titles = () => within(table()).getAllByRole('row').slice(1).map((row) => row.textContent ?? '')

describe('AlertsSection', () => {
  it('lists the alerts with the most severe first', () => {
    render(<AlertsSection source={ready(alertList())} onRetry={vi.fn()} />)
    const rows = titles()
    expect(rows).toHaveLength(3)
    expect(rows[0]).toContain('AWS のキー')      // CRITICAL
    expect(rows[1]).toContain('XSS の可能性')    // HIGH
    expect(rows[2]).toContain('lodash の脆弱性') // MEDIUM
  })

  it('shows the kind label from the config and the detecting tool', () => {
    render(<AlertsSection source={ready(alertList())} onRetry={vi.fn()} />)
    const row = within(table()).getByText('XSS の可能性').closest('tr') as HTMLElement
    expect(within(row).getByText(ALERT_KIND_VIEW.code.label)).toBeInTheDocument()
    expect(within(row).getByText('CodeQL')).toBeInTheDocument()
  })

  it('links the title only when the URL is http(s)', () => {
    render(<AlertsSection source={ready(alertList())} onRetry={vi.fn()} />)
    const safe = within(table()).getByRole('link', { name: /XSS の可能性/ })
    expect(safe).toHaveAttribute('href', 'https://github.com/owner/alpha/security/code-scanning/2')
    expect(safe).toHaveAttribute('rel', 'noopener noreferrer')
    // javascript: の URL は、リンクにしない（文字だけ出す）
    expect(within(table()).queryByRole('link', { name: /lodash の脆弱性/ })).not.toBeInTheDocument()
    expect(within(table()).getByText('lodash の脆弱性')).toBeInTheDocument()
  })

  it('filters by kind and by severity', async () => {
    const user = userEvent.setup()
    render(<AlertsSection source={ready(alertList())} onRetry={vi.fn()} />)

    await user.selectOptions(screen.getByRole('combobox', { name: POSTURE_TEXT.alerts.kind }), 'code')
    expect(titles()).toHaveLength(1)
    expect(titles()[0]).toContain('XSS の可能性')

    await user.selectOptions(screen.getByRole('combobox', { name: POSTURE_TEXT.alerts.kind }), '')
    await user.selectOptions(screen.getByRole('combobox', { name: POSTURE_TEXT.alerts.severity }), 'MEDIUM')
    expect(titles()).toHaveLength(1)
    expect(titles()[0]).toContain('lodash の脆弱性')
  })

  it('lists the sources that could not be fetched, each with its reason', () => {
    render(<AlertsSection source={ready(alertList())} onRetry={vi.fn()} />)
    const note = screen.getByRole('region', { name: POSTURE_TEXT.alerts.unavailableTitle })
    expect(note).toHaveTextContent('owner/web')
    expect(note).toHaveTextContent(ALERT_KIND_VIEW.secret.label)
    expect(note).toHaveTextContent('HTTP 404')
  })

  it('says there are no open alerts, but still lists the unavailable sources', () => {
    const list = AlertList.fromResponse({
      total: 0, data: [], unavailable: [{ kind: 'code', repo_full_name: 'owner/x', reason: null }],
    })
    render(<AlertsSection source={ready(list)} onRetry={vi.fn()} />)
    expect(screen.getByText(POSTURE_TEXT.alerts.empty)).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.getByRole('region', { name: POSTURE_TEXT.alerts.unavailableTitle })).toHaveTextContent(
      POSTURE_TEXT.alerts.unknownReason,
    )
  })

  it('shows the reason and a retry button when loading failed', async () => {
    const user = userEvent.setup()
    const onRetry = vi.fn()
    render(<AlertsSection source={failed('API error 500: /api/github-alerts')} onRetry={onRetry} />)
    expect(screen.getByRole('alert')).toHaveTextContent(POSTURE_TEXT.loadFailed)
    expect(screen.getByRole('alert')).not.toHaveTextContent('API error')
    await user.click(screen.getByRole('button', { name: POSTURE_TEXT.retry }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('shows a loading state', () => {
    render(<AlertsSection source={loading()} onRetry={vi.fn()} />)
    expect(screen.getByRole('status', { name: POSTURE_TEXT.loading })).toBeInTheDocument()
  })
})
