import { RefreshCw } from 'lucide-react'

// 画面の見出しの右に置く、再読み込みのボタン（KEV・OSV・DEPSCAN・CODESCAN・各小タブ・態勢・概要で共通）。
// 読み込み中は、アイコンを回して、押せなくする（二重に取得しない）
export function ReloadButton({ onReload, busy, label = '再読み込み' }: {
  onReload: () => void
  busy: boolean
  // ボタンの名前（アクセシブルな名前とツールチップ）。画面ごとに区別したいときに指定する
  label?: string
}) {
  return (
    <button
      type="button"
      onClick={onReload}
      disabled={busy}
      className="shrink-0 text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
      title={label}
      aria-label={label}
    >
      <RefreshCw size={13} className={busy ? 'animate-spin' : ''} aria-hidden="true" />
    </button>
  )
}
