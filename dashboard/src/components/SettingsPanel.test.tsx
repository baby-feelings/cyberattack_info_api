import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SettingsPanel } from './SettingsPanel'
import * as authApi from '../api/auth'

vi.mock('../api/auth', async () => {
  const actual = await vi.importActual<typeof import('../api/auth')>('../api/auth')
  return {
    ...actual,
    fetchNotificationSettings: vi.fn(),
    putNotificationSettings: vi.fn(),
    deleteNotificationSettings: vi.fn(),
  }
})

function setUrl(search: string) {
  window.history.pushState({}, '', `/${search}`)
}

describe('SettingsPanel', () => {
  const onClose = vi.fn()

  beforeEach(() => {
    localStorage.clear()
    setUrl('')
    vi.mocked(authApi.fetchNotificationSettings).mockResolvedValue({
      slack_webhook_url: null, notifications_enabled: true,
    })
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it('shows the login prompt when there is no session', async () => {
    render(<SettingsPanel onClose={onClose} />)
    await waitFor(() => expect(screen.getByText('GitHubでログイン')).toBeInTheDocument())
  })

  it('shows the notification form once logged in and loads existing settings', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    vi.mocked(authApi.fetchNotificationSettings).mockResolvedValue({
      slack_webhook_url: 'https://hooks.slack.com/services/existing', notifications_enabled: true,
    })

    render(<SettingsPanel onClose={onClose} />)

    await waitFor(() => expect(authApi.fetchNotificationSettings).toHaveBeenCalledWith('tok-abc'))
    const input = await screen.findByLabelText('Slack Incoming Webhook URL')
    expect(input).toHaveValue('https://hooks.slack.com/services/existing')
    expect(screen.getByText('登録解除')).toBeInTheDocument()
  })

  it('registers a new webhook and shows success', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    vi.mocked(authApi.putNotificationSettings).mockResolvedValue({
      slack_webhook_url: 'https://hooks.slack.com/services/new', notifications_enabled: true,
    })
    const user = userEvent.setup()

    render(<SettingsPanel onClose={onClose} />)
    const input = await screen.findByLabelText('Slack Incoming Webhook URL')
    await user.type(input, 'https://hooks.slack.com/services/new')
    await user.click(screen.getByText('テスト送信して保存'))

    await waitFor(() => expect(authApi.putNotificationSettings).toHaveBeenCalledWith(
      'tok-abc', 'https://hooks.slack.com/services/new',
    ))
    await waitFor(() => expect(screen.getByText('テスト送信に成功し、登録しました。')).toBeInTheDocument())
  })

  it('shows an error message when the test send fails', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    vi.mocked(authApi.putNotificationSettings).mockRejectedValue(
      new Error('Failed to send a test notification to this webhook URL.'),
    )
    const user = userEvent.setup()

    render(<SettingsPanel onClose={onClose} />)
    const input = await screen.findByLabelText('Slack Incoming Webhook URL')
    await user.type(input, 'https://hooks.slack.com/services/bad')
    await user.click(screen.getByText('テスト送信して保存'))

    await waitFor(() => expect(
      screen.getByText('Failed to send a test notification to this webhook URL.'),
    ).toBeInTheDocument())
  })

  it('unregisters the webhook', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    vi.mocked(authApi.fetchNotificationSettings).mockResolvedValue({
      slack_webhook_url: 'https://hooks.slack.com/services/existing', notifications_enabled: true,
    })
    vi.mocked(authApi.deleteNotificationSettings).mockResolvedValue({
      slack_webhook_url: null, notifications_enabled: true,
    })
    const user = userEvent.setup()

    render(<SettingsPanel onClose={onClose} />)
    await screen.findByDisplayValue('https://hooks.slack.com/services/existing')
    await user.click(screen.getByText('登録解除'))

    await waitFor(() => expect(authApi.deleteNotificationSettings).toHaveBeenCalledWith('tok-abc'))
    await waitFor(() => expect(screen.queryByText('登録解除')).not.toBeInTheDocument())
  })

  it('calls onClose when the backdrop is clicked', async () => {
    const user = userEvent.setup()
    render(<SettingsPanel onClose={onClose} />)
    await waitFor(() => expect(screen.getByText('設定')).toBeInTheDocument())
    await user.click(screen.getByTestId('settings-backdrop'))
    expect(onClose).toHaveBeenCalled()
  })

  it('calls onClose when the X button is clicked', async () => {
    const user = userEvent.setup()
    render(<SettingsPanel onClose={onClose} />)
    await waitFor(() => expect(screen.getByLabelText('閉じる')).toBeInTheDocument())
    await user.click(screen.getByLabelText('閉じる'))
    expect(onClose).toHaveBeenCalled()
  })
})
