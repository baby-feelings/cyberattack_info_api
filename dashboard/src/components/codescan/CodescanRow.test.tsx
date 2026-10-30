import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { CodescanRow } from './CodescanRow'
import type { CodeFindingOut } from '../../api/client'

function makeItem(overrides: Partial<CodeFindingOut> = {}): CodeFindingOut {
  return {
    repo_full_name: 'alice/api', file_path: '.github/workflows/ci.yml', line_start: 3, line_end: 3,
    rule_id: 'zizmor:artipacked', message: '認証情報が残ります', severity: 'WARNING',
    cwe_ids: [], owasp_categories: [], code_snippet: 'uses: actions/checkout@v4',
    cvss_score: null, cvss_vector: null, tool: 'zizmor', detected_at: '2026-10-30T00:00:00Z',
    resolved_at: null, exception_key: '.github/workflows/ci.yml|zizmor:artipacked', exception: null,
    ...overrides,
  }
}

function renderRow(item: CodeFindingOut, authToken?: string) {
  return render(
    <table><tbody><CodescanRow item={item} authToken={authToken} /></tbody></table>,
  )
}

describe('CodescanRow exceptions (Issue #403)', () => {
  it('tags a finding that has an exception', () => {
    renderRow(makeItem({
      exception: { id: 1, status: 'not_affected', reason: '意図的', expires_at: null, approver: 'alice' },
    }))
    expect(screen.getByText('影響なし')).toBeInTheDocument()
  })

  it('does not tag a finding without one', () => {
    renderRow(makeItem())
    expect(screen.queryByText('影響なし')).not.toBeInTheDocument()
  })

  it('offers the exception form in the expanded detail when logged in', () => {
    renderRow(makeItem(), 'tok')
    fireEvent.click(screen.getByText(/ci\.yml:3/))
    expect(screen.getByRole('button', { name: '例外にする' })).toBeInTheDocument()
  })

  it('hides the form without a login', () => {
    renderRow(makeItem())
    fireEvent.click(screen.getByText(/ci\.yml:3/))
    expect(screen.queryByRole('button', { name: '例外にする' })).not.toBeInTheDocument()
  })
})
