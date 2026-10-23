import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ActionSummary } from './ActionSummary'

describe('ActionSummary', () => {
  it('shows the count, the criteria and the total', () => {
    render(<ActionSummary count={8} criteria="CRITICAL・HIGH" total={16} loading={false} />)
    expect(screen.getByText('8')).toBeInTheDocument()
    expect(screen.getByText('件が対応必要（CRITICAL・HIGH）')).toBeInTheDocument()
    expect(screen.getByText('未解決 16 件のうち')).toBeInTheDocument()
  })

  it('shows a completion message when nothing needs action', () => {
    render(<ActionSummary count={0} criteria="重大" total={2} loading={false} />)
    expect(screen.getByText('対応が必要な脆弱性はありません')).toBeInTheDocument()
    expect(screen.getByText('（未解決 2 件は、重大以外）')).toBeInTheDocument()
  })

  it('omits the total when it is unknown', () => {
    render(<ActionSummary count={3} criteria="重大" total={null} loading={false} />)
    expect(screen.queryByText(/件のうち/)).not.toBeInTheDocument()
  })

  it('shows a loading placeholder instead of a misleading number', () => {
    render(<ActionSummary count={0} criteria="重大" total={null} loading />)
    expect(screen.getByRole('status', { name: '集計中' })).toBeInTheDocument()
    expect(screen.queryByText('対応が必要な脆弱性はありません')).not.toBeInTheDocument()
  })
})
