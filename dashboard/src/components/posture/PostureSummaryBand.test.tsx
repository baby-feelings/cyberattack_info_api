import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AlertList } from './model/AlertList'
import { AuditMatrix } from './model/AuditMatrix'
import { PostureSummary } from './model/PostureSummary'
import { PostureSummaryBand } from './PostureSummaryBand'
import { POSTURE_TEXT } from './postureConfig'
import { alertList, auditMatrix, sites } from './testFixtures'

describe('PostureSummaryBand', () => {
  it('shows the open alerts, the audit rate and the site issues', () => {
    const summary = new PostureSummary({ alerts: alertList(), audit: auditMatrix(), sites: sites() })
    render(<PostureSummaryBand summary={summary} />)

    const band = screen.getByRole('group', { name: '件数の集計' })
    expect(band).toHaveTextContent(`3${POSTURE_TEXT.summary.openAlerts}`)
    expect(band).toHaveTextContent(`75${POSTURE_TEXT.summary.auditRate}`)
    expect(band).toHaveTextContent(`1${POSTURE_TEXT.summary.siteIssues}`)
    expect(screen.queryByText(new RegExp(POSTURE_TEXT.summary.unknownPrefix))).not.toBeInTheDocument()
  })

  it('shows 0 when a source was fetched and is empty', () => {
    const summary = new PostureSummary({
      alerts: AlertList.fromResponse({ total: 0, data: [], unavailable: [] }), audit: new AuditMatrix([]), sites: [],
    })
    render(<PostureSummaryBand summary={summary} />)
    expect(screen.getByRole('group', { name: '件数の集計' })).toHaveTextContent(`0${POSTURE_TEXT.summary.openAlerts}`)
  })

  it('names the sources that could not be fetched instead of showing 0 for them', () => {
    const summary = new PostureSummary({ alerts: null, audit: auditMatrix(), sites: null })
    render(<PostureSummaryBand summary={summary} />)

    const band = screen.getByRole('group', { name: '件数の集計' })
    expect(band).not.toHaveTextContent(POSTURE_TEXT.summary.openAlerts)
    expect(band).not.toHaveTextContent(POSTURE_TEXT.summary.siteIssues)
    expect(screen.getByText(
      `${POSTURE_TEXT.summary.unknownPrefix} ${POSTURE_TEXT.sources.alerts}・${POSTURE_TEXT.sources.sites}`,
    )).toBeInTheDocument()
  })
})
