import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { OsvPanel } from './OsvPanel'
import { fetchOsvList, fetchOsvStats, type OsvVulnerabilityOut } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return { ...actual, fetchOsvList: vi.fn(), fetchOsvStats: vi.fn() }
})

const mockedList = vi.mocked(fetchOsvList)
const mockedStats = vi.mocked(fetchOsvStats)

function item(id: string, modified: string): OsvVulnerabilityOut {
  return {
    osv_id: id, ecosystem: 'PyPI', package_name: `pkg-${id}`, aliases: [], summary: 's', details: 'd',
    severity: 'HIGH', cvss_score: 7.5, affected_versions: [], fixed_versions: [], references: [],
    published: modified, modified,
  }
}

const DATA = [
  item('A', '2026-06-15T03:00:00Z'),
  item('B', '2026-06-15T05:00:00Z'),
  item('C', '2026-06-14T03:00:00Z'),
]

describe('OsvPanel date dividers', () => {
  afterEach(() => vi.resetAllMocks())

  it('divides by modified day, and hides the dividers when sorted by CVSS', async () => {
    mockedList.mockResolvedValue({ total: 3, page: 1, per_page: 30, data: DATA })
    mockedStats.mockResolvedValue({ total: 3, ecosystems: [], severities: [], monthly_trend: [] })
    const user = userEvent.setup()

    render(<OsvPanel />)
    await waitFor(() => expect(screen.getAllByRole('row', { name: /の区切り$/ })).toHaveLength(2))
    expect(screen.getByRole('row', { name: '2026年6月15日の区切り' })).toBeInTheDocument()
    expect(screen.getByRole('row', { name: '2026年6月14日の区切り' })).toBeInTheDocument()

    await user.click(screen.getByText('CVSS'))
    await waitFor(() => expect(screen.queryAllByRole('row', { name: /の区切り$/ })).toHaveLength(0))
  })
})
