import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { POSTURE_TEXT, SITE_SOURCE_LABELS } from './postureConfig'
import { SiteMonitorSection } from './SiteMonitorSection'
import { failed, loading, ready, sites } from './testFixtures'

vi.mock('../freshness/LastFetched', () => ({ LastFetched: () => null }))

const table = () => screen.getByRole('table', { name: POSTURE_TEXT.sites.title })

describe('SiteMonitorSection', () => {
  it('shows each site with its TLS days left and its findings', () => {
    render(<SiteMonitorSection source={ready(sites())} onRetry={vi.fn()} />)
    const bad = within(table()).getByText('https://bad.example').closest('tr') as HTMLElement
    expect(bad).toHaveTextContent(`3${POSTURE_TEXT.sites.tlsUnit}`)
    expect(bad).toHaveTextContent('TLS 証明書の期限が、あと3日です')

    const ok = within(table()).getByText('https://ok.example').closest('tr') as HTMLElement
    expect(ok).toHaveTextContent(`90${POSTURE_TEXT.sites.tlsUnit}`)
    expect(ok).toHaveTextContent(POSTURE_TEXT.sites.noFindings)
  })

  it('shows where each site came from, with an unknown source shown as it is', () => {
    const [site] = sites()
    const other = Object.assign(Object.create(Object.getPrototypeOf(site)), site, { url: 'https://x.example', source: 'new-source' })
    render(<SiteMonitorSection source={ready([site, other])} onRetry={vi.fn()} />)

    expect(within(table()).getByRole('columnheader', { name: POSTURE_TEXT.sites.columns.source })).toBeInTheDocument()
    const first = within(table()).getByText('https://bad.example').closest('tr') as HTMLElement
    expect(first).toHaveTextContent(SITE_SOURCE_LABELS.homepage)
    const second = within(table()).getByText('https://x.example').closest('tr') as HTMLElement
    expect(second).toHaveTextContent('new-source')
  })

  it('shows a dash when the TLS days could not be read', () => {
    const [site] = sites()
    const unknown = Object.assign(Object.create(Object.getPrototypeOf(site)), site, { tlsDaysLeft: null })
    render(<SiteMonitorSection source={ready([unknown])} onRetry={vi.fn()} />)
    expect(within(table()).getByText('—')).toBeInTheDocument()
  })

  it('says there is no result when no site is monitored', () => {
    render(<SiteMonitorSection source={ready([])} onRetry={vi.fn()} />)
    expect(screen.getByText(POSTURE_TEXT.sites.empty)).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('shows the reason and a retry button when loading failed', async () => {
    const user = userEvent.setup()
    const onRetry = vi.fn()
    render(<SiteMonitorSection source={failed('API error 500: /api/site-monitor')} onRetry={onRetry} />)
    expect(screen.getByRole('alert')).toHaveTextContent(POSTURE_TEXT.loadFailed)
    expect(screen.getByRole('alert')).not.toHaveTextContent('API error')
    await user.click(screen.getByRole('button', { name: POSTURE_TEXT.retry }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('shows a loading state', () => {
    render(<SiteMonitorSection source={loading()} onRetry={vi.fn()} />)
    expect(screen.getByRole('status', { name: POSTURE_TEXT.loading })).toBeInTheDocument()
  })
})
