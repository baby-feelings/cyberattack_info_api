import { useState } from 'react'
import { ShieldOff } from 'lucide-react'
import {
  createException, revokeException, EXCEPTION_STATUS_LABELS,
  type ExceptionStatus, type FindingExceptionSummary,
} from '../../api/exceptions'

// 受容の期限の既定（登録日から何日後か）。長すぎる放置を避けるため、短めにしている
const DEFAULT_EXPIRY_DAYS = 90

// <input type="date"> の値（YYYY-MM-DD）。ローカルの日付で、N 日後を返す
function dateAfterDays(days: number): string {
  const d = new Date()
  d.setDate(d.getDate() + days)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

// 日付（YYYY-MM-DD）の終わりを、UTC の ISO 8601 にする（その日いっぱいを期限にする）
function endOfDayIso(date: string): string {
  return `${date}T23:59:59Z`
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('ja-JP', { year: 'numeric', month: 'numeric', day: 'numeric' })
}

// 例外の状態を示す小さなタグ（一覧の行に出す）
export function ExceptionTag({ exception }: { exception: FindingExceptionSummary }) {
  return (
    <span
      title={`${EXCEPTION_STATUS_LABELS[exception.status]}: ${exception.reason}`}
      className="inline-flex items-center gap-0.5 px-1 py-0.5 rounded text-[9px] font-bold bg-slate-500/20 text-slate-300 border border-slate-500/40 whitespace-nowrap"
    >
      <ShieldOff size={8} />
      {EXCEPTION_STATUS_LABELS[exception.status]}
    </span>
  )
}

interface ExceptionControlProps {
  kind: 'dependency' | 'code'
  repo: string
  // 検知の同一性キー（一覧の `exception_key`）
  findingKey: string
  exception: FindingExceptionSummary | null | undefined
  // ログイン中のセッショントークン（無ければ、操作できない）
  authToken?: string
  // 登録・解除に成功したとき（一覧を読み直す）
  onChanged: () => void
}

// 検知ごとの「例外にする」（受容・誤検知・影響なし）と、「解除」の操作。
// 例外にした検知は、通知・「要対応」の件数・対応期限から外れる（一覧では確認できる）。
export function ExceptionControl({
  kind, repo, findingKey, exception, authToken, onChanged,
}: ExceptionControlProps) {
  const [editing, setEditing] = useState(false)
  const [status, setStatus] = useState<ExceptionStatus>('accepted')
  const [reason, setReason] = useState('')
  const [expiry, setExpiry] = useState(() => dateAfterDays(DEFAULT_EXPIRY_DAYS))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // 認証なし（API キーの閲覧など）では、操作できない。有効な例外の表示だけを行う
  const canEdit = Boolean(authToken)

  async function run(action: () => Promise<void>) {
    setBusy(true)
    setError(null)
    try {
      await action()
      setEditing(false)
      setReason('')
      onChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : '操作に失敗しました')
    } finally {
      setBusy(false)
    }
  }

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!authToken) return
    run(() => createException(authToken, {
      kind, repo_full_name: repo, finding_key: findingKey, status, reason,
      expires_at: expiry ? endOfDayIso(expiry) : null,
    }))
  }

  if (exception) {
    return (
      <div role="group" aria-label="例外" className="flex flex-col gap-1 rounded border border-slate-700 bg-slate-900/60 px-2 py-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <ExceptionTag exception={exception} />
          {exception.expires_at && (
            <span className="text-[10px] text-slate-500">期限 {formatDate(exception.expires_at)}</span>
          )}
          <span className="text-[10px] text-slate-600">承認者: {exception.approver}</span>
          {canEdit && (
            <button
              type="button"
              disabled={busy}
              onClick={() => authToken && run(() => revokeException(authToken, exception.id))}
              className="ml-auto text-[10px] text-slate-400 hover:text-slate-200 underline disabled:opacity-40"
            >
              解除
            </button>
          )}
        </div>
        <p className="text-slate-400 whitespace-pre-wrap">理由: {exception.reason}</p>
        {error && <p role="alert" className="text-[10px] text-red-400">{error}</p>}
      </div>
    )
  }

  if (!canEdit) return null

  if (!editing) {
    return (
      <button
        type="button"
        onClick={() => setEditing(true)}
        className="self-start text-[10px] text-slate-400 hover:text-slate-200 underline"
      >
        例外にする
      </button>
    )
  }

  return (
    <form
      aria-label="例外の登録"
      onSubmit={submit}
      className="flex flex-col gap-2 rounded border border-slate-700 bg-slate-900/60 p-2"
    >
      <div className="flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-1 text-[11px] text-slate-400">
          状態
          <select
            value={status}
            onChange={e => {
              const next = e.target.value as ExceptionStatus
              setStatus(next)
              // 受容は期限が必須（既定を入れる）。誤検知・影響なしは、期限なしを既定にする
              setExpiry(next === 'accepted' ? dateAfterDays(DEFAULT_EXPIRY_DAYS) : '')
            }}
            className="rounded bg-slate-800 border border-slate-700 px-1 py-0.5 text-[11px] text-slate-200"
          >
            {(Object.keys(EXCEPTION_STATUS_LABELS) as ExceptionStatus[]).map(s => (
              <option key={s} value={s}>{EXCEPTION_STATUS_LABELS[s]}</option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1 text-[11px] text-slate-400">
          期限{status === 'accepted' ? '（必須）' : '（任意）'}
          <input
            type="date"
            value={expiry}
            required={status === 'accepted'}
            onChange={e => setExpiry(e.target.value)}
            className="rounded bg-slate-800 border border-slate-700 px-1 py-0.5 text-[11px] text-slate-200"
          />
        </label>
      </div>
      <label className="flex flex-col gap-1 text-[11px] text-slate-400">
        理由（必須）
        <textarea
          value={reason}
          required
          maxLength={2000}
          rows={2}
          onChange={e => setReason(e.target.value)}
          placeholder="例: 修正版が公開されていない／到達できないコードのため"
          className="rounded bg-slate-800 border border-slate-700 px-2 py-1 text-[11px] text-slate-200"
        />
      </label>
      {error && <p role="alert" className="text-[10px] text-red-400">{error}</p>}
      <div className="flex gap-2">
        <button
          type="submit"
          disabled={busy || reason.trim() === ''}
          className="px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 text-[11px] text-white disabled:opacity-40"
        >
          登録
        </button>
        <button
          type="button"
          onClick={() => { setEditing(false); setError(null) }}
          className="px-2 py-1 rounded text-[11px] text-slate-400 hover:text-slate-200"
        >
          キャンセル
        </button>
      </div>
    </form>
  )
}
