import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ExceptionControl, ExceptionTag } from './ExceptionControl'
import * as exceptionsApi from '../../api/exceptions'
import type { FindingExceptionSummary } from '../../api/exceptions'

vi.mock('../../api/exceptions', async importOriginal => {
  const actual = await importOriginal<typeof import('../../api/exceptions')>()
  return { ...actual, createException: vi.fn(), revokeException: vi.fn() }
})

const EXCEPTION: FindingExceptionSummary = {
  id: 7, status: 'accepted', reason: '修正版が無い', expires_at: '2026-12-31T00:00:00Z', approver: 'alice',
}

function setup(props: Partial<React.ComponentProps<typeof ExceptionControl>> = {}) {
  const onChanged = vi.fn()
  render(
    <ExceptionControl
      kind="dependency"
      repo="alice/api"
      findingKey="npm|lodash|GHSA-1"
      exception={null}
      authToken="tok"
      onChanged={onChanged}
      {...props}
    />,
  )
  return { onChanged, user: userEvent.setup() }
}

describe('ExceptionControl', () => {
  beforeEach(() => {
    vi.mocked(exceptionsApi.createException).mockReset().mockResolvedValue()
    vi.mocked(exceptionsApi.revokeException).mockReset().mockResolvedValue()
  })

  it('renders nothing without a login and without an exception', () => {
    setup({ authToken: undefined })
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('shows the exception read-only without a login (no revoke button)', () => {
    setup({ authToken: undefined, exception: EXCEPTION })
    expect(screen.getByText('理由: 修正版が無い')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '解除' })).not.toBeInTheDocument()
  })

  it('registers an acceptance with a reason and an end-of-day expiry', async () => {
    const { user, onChanged } = setup()

    await user.click(screen.getByRole('button', { name: '例外にする' }))
    await user.type(screen.getByLabelText(/理由/), '修正版が無い')
    await user.click(screen.getByRole('button', { name: '登録' }))

    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1))
    const [token, input] = vi.mocked(exceptionsApi.createException).mock.calls[0]
    expect(token).toBe('tok')
    expect(input).toMatchObject({
      kind: 'dependency', repo_full_name: 'alice/api', finding_key: 'npm|lodash|GHSA-1',
      status: 'accepted', reason: '修正版が無い',
    })
    expect(input.expires_at).toMatch(/T23:59:59Z$/)
  })

  it('sends no expiry for a false positive', async () => {
    const { user } = setup()

    await user.click(screen.getByRole('button', { name: '例外にする' }))
    await user.selectOptions(screen.getByLabelText('状態'), 'false_positive')
    await user.type(screen.getByLabelText(/理由/), '誤検知')
    await user.click(screen.getByRole('button', { name: '登録' }))

    await waitFor(() => expect(exceptionsApi.createException).toHaveBeenCalled())
    expect(vi.mocked(exceptionsApi.createException).mock.calls[0][1]).toMatchObject({
      status: 'false_positive', expires_at: null,
    })
  })

  it('restores the default expiry when switching back to an acceptance', async () => {
    const { user } = setup()
    await user.click(screen.getByRole('button', { name: '例外にする' }))
    await user.selectOptions(screen.getByLabelText('状態'), 'not_affected')
    expect(screen.getByLabelText(/期限/)).toHaveValue('')

    await user.selectOptions(screen.getByLabelText('状態'), 'accepted')

    expect(screen.getByLabelText(/期限/)).not.toHaveValue('')
  })

  it('keeps the register button disabled until a reason is typed', async () => {
    const { user } = setup()
    await user.click(screen.getByRole('button', { name: '例外にする' }))

    expect(screen.getByRole('button', { name: '登録' })).toBeDisabled()
    await user.type(screen.getByLabelText(/理由/), '  ')
    expect(screen.getByRole('button', { name: '登録' })).toBeDisabled()
  })

  it('shows the server error and keeps the form open', async () => {
    vi.mocked(exceptionsApi.createException).mockRejectedValueOnce(new Error('期限は、365日以内にしてください。'))
    const { user, onChanged } = setup()

    await user.click(screen.getByRole('button', { name: '例外にする' }))
    await user.type(screen.getByLabelText(/理由/), 'r')
    await user.click(screen.getByRole('button', { name: '登録' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('期限は、365日以内にしてください。')
    expect(onChanged).not.toHaveBeenCalled()
    expect(screen.getByRole('form', { name: '例外の登録' })).toBeInTheDocument()
  })

  it('falls back to a generic message for a non-Error failure', async () => {
    vi.mocked(exceptionsApi.createException).mockRejectedValueOnce('x')
    const { user } = setup()
    await user.click(screen.getByRole('button', { name: '例外にする' }))
    await user.type(screen.getByLabelText(/理由/), 'r')
    await user.click(screen.getByRole('button', { name: '登録' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('操作に失敗しました')
  })

  it('cancels the form', async () => {
    const { user } = setup()
    await user.click(screen.getByRole('button', { name: '例外にする' }))
    await user.click(screen.getByRole('button', { name: 'キャンセル' }))

    expect(screen.getByRole('button', { name: '例外にする' })).toBeInTheDocument()
  })

  it('shows an active exception with its expiry, approver and reason, and revokes it', async () => {
    const { user, onChanged } = setup({ exception: EXCEPTION })

    expect(screen.getByText('受容')).toBeInTheDocument()
    expect(screen.getByText(/期限 2026\/12\/31/)).toBeInTheDocument()
    expect(screen.getByText('承認者: alice')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '解除' }))

    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1))
    expect(exceptionsApi.revokeException).toHaveBeenCalledWith('tok', 7)
  })

  it('shows an error when revoking fails', async () => {
    vi.mocked(exceptionsApi.revokeException).mockRejectedValueOnce(new Error('既に終了しています'))
    const { user } = setup({ exception: EXCEPTION })

    await user.click(screen.getByRole('button', { name: '解除' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('既に終了しています')
  })

  it('omits the expiry for an exception without one', () => {
    setup({ exception: { ...EXCEPTION, status: 'false_positive', expires_at: null } })
    expect(screen.getByText('誤検知')).toBeInTheDocument()
    expect(screen.queryByText(/期限/)).not.toBeInTheDocument()
  })
})

describe('ExceptionTag', () => {
  it('labels the status and carries the reason as a tooltip', () => {
    render(<ExceptionTag exception={{ ...EXCEPTION, status: 'not_affected' }} />)
    expect(screen.getByText('影響なし')).toHaveAttribute('title', '影響なし: 修正版が無い')
  })
})
