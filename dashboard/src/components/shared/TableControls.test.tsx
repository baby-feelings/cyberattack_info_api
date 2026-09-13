import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import {
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons, SearchBox, SortSelector,
} from './TableControls'

const CLASS_MAP = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
}

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

  it('marks ALL active with the default activeAllClass when nothing is selected', () => {
    render(
      <SeverityFilterButtons
        severities={['ALL', 'CRITICAL']}
        active={null}
        onSelect={vi.fn()}
        classMap={CLASS_MAP}
      />,
    )
    expect(screen.getByText('ALL').className).toContain('bg-slate-700')
  })

  it('accepts a custom activeAllClass', () => {
    render(
      <SeverityFilterButtons
        severities={['ALL', 'CRITICAL']}
        active={null}
        onSelect={vi.fn()}
        classMap={CLASS_MAP}
        activeAllClass="bg-violet-600 text-white"
      />,
    )
    expect(screen.getByText('ALL').className).toContain('bg-violet-600')
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

  it('calls onChange with "modified" when the 更新日 button is clicked', () => {
    const onChange = vi.fn()
    render(<SortSelector sortBy="cvss" onChange={onChange} activeClass="bg-violet-600" />)
    fireEvent.click(screen.getByText('更新日'))
    expect(onChange).toHaveBeenCalledWith('modified')
  })

  it('applies the active class to the currently selected sort', () => {
    render(<SortSelector sortBy="cvss" onChange={vi.fn()} activeClass="bg-violet-600" />)
    expect(screen.getByText('CVSS').className).toContain('bg-violet-600')
    expect(screen.getByText('更新日').className).not.toContain('bg-violet-600')
  })
})
