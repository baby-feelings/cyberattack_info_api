import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import {
  SeverityBadge, ChartCard, SeverityPieChart, MonthlyBarChart,
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons, SearchBox, SortSelector,
} from './VulnPanelParts'

const CLASS_MAP = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
}

describe('SeverityBadge', () => {
  it('renders the severity text with its mapped class', () => {
    render(<SeverityBadge severity="CRITICAL" classMap={CLASS_MAP} />)
    const badge = screen.getByText('CRITICAL')
    expect(badge.className).toContain('text-red-400')
  })

  it('falls back to a generic class for an unmapped severity', () => {
    render(<SeverityBadge severity="LOW" classMap={CLASS_MAP} />)
    const badge = screen.getByText('LOW')
    expect(badge.className).toContain('bg-slate-800')
  })

  it('renders "N/A" for a null severity', () => {
    render(<SeverityBadge severity={null} classMap={CLASS_MAP} />)
    expect(screen.getByText('N/A')).toBeInTheDocument()
  })
})

describe('ChartCard', () => {
  it('shows the loading label while loading', () => {
    render(
      <ChartCard icon={<span />} title="Test Chart" loading isEmpty={false} height={100}>
        <div>content</div>
      </ChartCard>,
    )
    expect(screen.getByText('読み込み中...')).toBeInTheDocument()
    expect(screen.queryByText('content')).not.toBeInTheDocument()
  })

  it('shows the empty label when not loading and empty', () => {
    render(
      <ChartCard icon={<span />} title="Test Chart" loading={false} isEmpty height={100}>
        <div>content</div>
      </ChartCard>,
    )
    expect(screen.getByText('データなし')).toBeInTheDocument()
  })

  it('renders children and footer once loaded with data', () => {
    render(
      <ChartCard
        icon={<span />}
        title="Test Chart"
        loading={false}
        isEmpty={false}
        height={100}
        footer={<span>legend</span>}
      >
        <div>content</div>
      </ChartCard>,
    )
    expect(screen.getByText('content')).toBeInTheDocument()
    expect(screen.getByText('legend')).toBeInTheDocument()
  })

  it('hides the footer while loading', () => {
    render(
      <ChartCard icon={<span />} title="Test Chart" loading isEmpty={false} height={100} footer={<span>legend</span>}>
        <div>content</div>
      </ChartCard>,
    )
    expect(screen.queryByText('legend')).not.toBeInTheDocument()
  })
})

describe('SeverityPieChart', () => {
  it('reports empty when all counts are zero or N/A', () => {
    render(
      <SeverityPieChart
        icon={<span />}
        data={[{ severity: 'N/A', count: 5 }, { severity: 'LOW', count: 0 }]}
        colorMap={{}}
        loading={false}
      />,
    )
    expect(screen.getByText('データなし')).toBeInTheDocument()
  })

  it('renders a legend entry per non-zero severity', () => {
    render(
      <SeverityPieChart
        icon={<span />}
        data={[{ severity: 'CRITICAL', count: 3 }, { severity: 'HIGH', count: 2 }]}
        colorMap={{ CRITICAL: '#ef4444', HIGH: '#f97316' }}
        loading={false}
      />,
    )
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })
})

describe('MonthlyBarChart', () => {
  it('shows empty state for an empty dataset', () => {
    render(
      <MonthlyBarChart icon={<span />} title="Monthly" data={[]} barColor="#7c3aed" loading={false} />,
    )
    expect(screen.getByText('データなし')).toBeInTheDocument()
  })

  it('renders the given title', () => {
    render(
      <MonthlyBarChart
        icon={<span />}
        title="月別トレンド"
        data={[{ year_month: '2026-06', count: 5 }]}
        barColor="#7c3aed"
        loading={false}
      />,
    )
    expect(screen.getByText('月別トレンド')).toBeInTheDocument()
  })
})

describe('TableLoadingSkeleton', () => {
  it('renders 5 skeleton rows, each with one block per column width', () => {
    const { container } = render(<TableLoadingSkeleton columnWidths={['w-10', 'w-20']} />)
    const rows = container.querySelectorAll(':scope > div > div')
    expect(rows.length).toBe(5)
    const blocks = container.querySelectorAll(':scope > div > div > div')
    expect(blocks.length).toBe(10) // 5 rows x 2 columns
  })
})

describe('EmptyState', () => {
  it('renders the given message', () => {
    render(<EmptyState icon={<span />} message="該当するデータはありません" />)
    expect(screen.getByText('該当するデータはありません')).toBeInTheDocument()
  })
})

describe('Pagination', () => {
  it('renders nothing when there is only one page', () => {
    const { container } = render(
      <Pagination page={1} totalPages={1} total={3} onPageChange={vi.fn()} />,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('disables the previous button on the first page', () => {
    render(<Pagination page={1} totalPages={3} total={60} onPageChange={vi.fn()} />)
    expect(screen.getByText('← 前へ')).toBeDisabled()
    expect(screen.getByText('次へ →')).not.toBeDisabled()
  })

  it('disables the next button on the last page', () => {
    render(<Pagination page={3} totalPages={3} total={60} onPageChange={vi.fn()} />)
    expect(screen.getByText('次へ →')).toBeDisabled()
  })

  it('calls onPageChange with an incrementing updater when next is clicked', () => {
    const onPageChange = vi.fn()
    render(<Pagination page={1} totalPages={3} total={60} onPageChange={onPageChange} />)
    fireEvent.click(screen.getByText('次へ →'))
    expect(onPageChange).toHaveBeenCalledTimes(1)
    const updater = onPageChange.mock.calls[0][0]
    expect(updater(1)).toBe(2)
    expect(updater(3)).toBe(3) // clamped to totalPages
  })

  it('calls onPageChange with a decrementing updater when previous is clicked', () => {
    const onPageChange = vi.fn()
    render(<Pagination page={2} totalPages={3} total={60} onPageChange={onPageChange} />)
    fireEvent.click(screen.getByText('← 前へ'))
    const updater = onPageChange.mock.calls[0][0]
    expect(updater(2)).toBe(1)
    expect(updater(1)).toBe(1) // clamped to 1
  })
})

describe('SeverityFilterButtons', () => {
  it('renders a button per severity and calls onSelect when clicked', () => {
    const onSelect = vi.fn()
    render(
      <SeverityFilterButtons
        severities={['ALL', 'CRITICAL', 'HIGH']}
        active={null}
        onSelect={onSelect}
        classMap={CLASS_MAP}
      />,
    )
    fireEvent.click(screen.getByText('CRITICAL'))
    expect(onSelect).toHaveBeenCalledWith('CRITICAL')
  })

  it('marks the active severity distinctly from inactive ones', () => {
    render(
      <SeverityFilterButtons
        severities={['ALL', 'CRITICAL', 'HIGH']}
        active="CRITICAL"
        onSelect={vi.fn()}
        classMap={CLASS_MAP}
      />,
    )
    expect(screen.getByText('CRITICAL').className).toContain('text-red-400')
    expect(screen.getByText('HIGH').className).toContain('text-slate-500')
  })
})

describe('SearchBox', () => {
  it('calls onChange as the user types', () => {
    const onChange = vi.fn()
    render(
      <SearchBox
        value=""
        onChange={onChange}
        onClear={vi.fn()}
        placeholder="検索"
        searchIcon={<span />}
        clearIcon={<span />}
      />,
    )
    fireEvent.change(screen.getByPlaceholderText('検索'), { target: { value: 'apache' } })
    expect(onChange).toHaveBeenCalledWith('apache')
  })

  it('shows the clear button only when a value is present', () => {
    const { rerender } = render(
      <SearchBox value="" onChange={vi.fn()} onClear={vi.fn()} placeholder="検索" searchIcon={<span />} clearIcon={<span data-testid="clear-icon" />} />,
    )
    expect(screen.queryByTestId('clear-icon')).not.toBeInTheDocument()

    rerender(
      <SearchBox value="apache" onChange={vi.fn()} onClear={vi.fn()} placeholder="検索" searchIcon={<span />} clearIcon={<span data-testid="clear-icon" />} />,
    )
    expect(screen.getByTestId('clear-icon')).toBeInTheDocument()
  })

  it('calls onClear when the clear button is clicked', () => {
    const onClear = vi.fn()
    render(
      <SearchBox value="apache" onChange={vi.fn()} onClear={onClear} placeholder="検索" searchIcon={<span />} clearIcon={<span>x</span>} />,
    )
    fireEvent.click(screen.getByText('x'))
    expect(onClear).toHaveBeenCalled()
  })
})

describe('SortSelector', () => {
  it('calls onChange with the clicked sort key', () => {
    const onChange = vi.fn()
    render(<SortSelector sortBy="modified" onChange={onChange} activeClass="bg-violet-600" />)
    fireEvent.click(screen.getByText('CVSS'))
    expect(onChange).toHaveBeenCalledWith('cvss')
  })

  it('applies the active class to the currently selected sort', () => {
    render(<SortSelector sortBy="cvss" onChange={vi.fn()} activeClass="bg-violet-600" />)
    expect(screen.getByText('CVSS').className).toContain('bg-violet-600')
    expect(screen.getByText('更新日').className).not.toContain('bg-violet-600')
  })
})
