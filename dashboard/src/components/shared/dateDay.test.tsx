import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { formatDay, isNewDay } from './dateDay'
import { DateDividerRow } from './DateDividerRow'

describe('dateDay', () => {
  it('formats a day in Japanese', () => {
    expect(formatDay('2026-10-20')).toBe('2026年10月20日')
  })

  it('treats the first row as a new day', () => {
    expect(isNewDay(undefined, '2026-10-20')).toBe(true)
  })

  it('compares days, not instants', () => {
    // 同じ日の別時刻は区切らず、日が変わると区切る
    expect(isNewDay('2026-06-15T03:00:00Z', '2026-06-15T05:00:00Z')).toBe(false)
    expect(isNewDay('2026-06-15T03:00:00Z', '2026-06-14T03:00:00Z')).toBe(true)
  })
})

describe('DateDividerRow', () => {
  it('renders a labelled row spanning the table', () => {
    render(<table><tbody><DateDividerRow date="2026-10-20" colSpan={7} /></tbody></table>)
    const row = screen.getByRole('row', { name: '2026年10月20日の区切り' })
    expect(row.querySelector('td')).toHaveAttribute('colspan', '7')
  })
})
