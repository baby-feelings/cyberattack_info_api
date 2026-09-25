import { useEffect, useState } from 'react'
import { Bell, X } from 'lucide-react'
import { useGithubSession } from '../hooks/useGithubSession'
import {
  deleteNotificationSettings, fetchNotificationSettings, putNotificationSettings,
} from '../api/auth'
import { UnauthorizedError } from '../api/shared'

// 設定画面（Issue #227）: ログイン中ユーザー自身のSlack Webhook通知を登録・解除する。
// DEPSCAN/CODESCANと同じGitHubログインセッション（useGithubSession）を共有するため、
// どのタブでログインしていてもここで設定できる。
export function SettingsPanel({ onClose }: { onClose: () => void }) {
  const { session, checked, handleLogoutClick } = useGithubSession()

  return (
    <div
      data-testid="settings-backdrop"
      className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm flex items-start justify-center p-4 sm:p-8 overflow-y-auto"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg mt-8 sm:mt-16 rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <Bell size={18} className="text-violet-400" />
            <h2 className="text-base font-semibold text-white">設定</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 transition-colors p-1 rounded"
            aria-label="閉じる"
          >
            <X size={18} />
          </button>
        </div>

        {!checked ? (
          <p className="text-sm text-slate-500">確認中...</p>
        ) : !session ? (
          <div className="space-y-3">
            <p className="text-sm text-slate-400">
              Slack通知の登録にはGitHubアカウントでのログインが必要です。
            </p>
            <a
              href={`${import.meta.env.VITE_API_BASE_URL || 'https://cyberattack-info-api.onrender.com'}/auth/github/login`}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 text-white text-sm font-medium transition-colors"
            >
              GitHubでログイン
            </a>
          </div>
        ) : (
          <NotificationSettingsForm authToken={session.token} username={session.username} />
        )}

        {session && (
          <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between">
            <span className="text-xs text-slate-500">{session.username} でログイン中</span>
            <button
              onClick={handleLogoutClick}
              className="text-xs text-slate-500 hover:text-rose-400 transition-colors"
            >
              ログアウト
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function NotificationSettingsForm({ authToken, username }: { authToken: string; username: string }) {
  const [webhookUrl, setWebhookUrl] = useState('')
  const [registeredUrl, setRegisteredUrl] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    let cancelled = false
    fetchNotificationSettings(authToken)
      .then((res) => {
        if (cancelled) return
        setRegisteredUrl(res.slack_webhook_url)
        if (res.slack_webhook_url) setWebhookUrl(res.slack_webhook_url)
      })
      .catch((err) => {
        if (!cancelled && !(err instanceof UnauthorizedError)) {
          setError('通知設定の取得に失敗しました')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [authToken])

  async function handleSave() {
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      const res = await putNotificationSettings(authToken, webhookUrl.trim())
      setRegisteredUrl(res.slack_webhook_url)
      setSaved(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : '登録に失敗しました')
    } finally {
      setSaving(false)
    }
  }

  async function handleUnregister() {
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      await deleteNotificationSettings(authToken)
      setRegisteredUrl(null)
      setWebhookUrl('')
    } catch {
      setError('登録解除に失敗しました')
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <p className="text-sm text-slate-500">読み込み中...</p>

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-sm font-medium text-slate-200 mb-1">Slack通知</h3>
        <p className="text-xs text-slate-500 leading-relaxed">
          {username} さん自身のGitHubリポジトリに対するDEPSCAN・CODESCAN・DEPSOPSの
          検知結果を、登録したSlack Webhookへ通知します。加えて、KEV・OSV・JVNの
          最新脅威情報も通知されます。
        </p>
      </div>

      <div>
        <label className="block text-xs text-slate-500 mb-1.5" htmlFor="slack-webhook-url">
          Slack Incoming Webhook URL
        </label>
        <input
          id="slack-webhook-url"
          type="url"
          placeholder="https://hooks.slack.com/services/..."
          value={webhookUrl}
          onChange={(e) => setWebhookUrl(e.target.value)}
          className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500"
        />
      </div>

      {error && <p className="text-xs text-rose-400">{error}</p>}
      {saved && !error && (
        <p className="text-xs text-emerald-400">テスト送信に成功し、登録しました。</p>
      )}

      <div className="flex items-center gap-2">
        <button
          onClick={handleSave}
          disabled={saving || !webhookUrl.trim()}
          className="px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
        >
          {saving ? '送信中...' : 'テスト送信して保存'}
        </button>
        {registeredUrl && (
          <button
            onClick={handleUnregister}
            disabled={saving}
            className="px-4 py-2 rounded-lg border border-slate-700 hover:border-rose-500/50 hover:text-rose-400 disabled:opacity-40 text-slate-400 text-sm font-medium transition-colors"
          >
            登録解除
          </button>
        )}
      </div>
    </div>
  )
}
