import { useState, type FormEvent, type ReactNode } from 'react'

// OsvPanel・JvnPanel で共有する、テーブル一覧の制御系パーツ群
// （ローディングスケルトン・空状態・ページネーション・重要度フィルター・
// 検索ボックス・ソートセレクター）。

// ── ローディングスケルトン（テーブル用） ────────────────────────

export function TableLoadingSkeleton({ columnWidths }: { columnWidths: string[] }) {
  return (
    <div className="space-y-2 py-4">
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="flex items-center gap-3 py-2">
          {columnWidths.map((w, j) => (
            <div key={j} className={`h-4 bg-slate-800 rounded animate-pulse ${w}`} />
          ))}
        </div>
      ))}
    </div>
  )
}

// ── データなし状態 ────────────────────────────────────────────

export function EmptyState({ icon, message }: { icon: ReactNode; message: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-slate-600">
      {icon}
      <p className="text-sm">{message}</p>
      <p className="text-xs text-slate-700">クローラーがデータを取得すると表示されます</p>
    </div>
  )
}

// ── ページネーション ──────────────────────────────────────────

// ページ送りボタン共通のスタイル。スマホでも押しやすいよう高さ・余白を確保する
const PAGE_BTN_CLS =
  'flex items-center justify-center gap-1 min-h-9 px-2.5 sm:px-3 py-1.5 whitespace-nowrap rounded-lg bg-slate-800 hover:bg-slate-700 text-sm text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed transition-colors'

export function Pagination({
  page, totalPages, total, onPageChange, position = 'bottom',
}: {
  page: number
  totalPages: number
  total: number
  onPageChange: (updater: (p: number) => number) => void
  // 'top' はテーブル上部にも同じ操作を配置する場合に使う（区切り線を下側に出す）
  position?: 'top' | 'bottom'
}) {
  // 直接入力中のページ番号（確定するまでの下書き）
  const [jumpValue, setJumpValue] = useState('')
  if (totalPages <= 1) return null
  // 入力値を 1〜totalPages に丸めてそのページへ移動する。数字以外・空の場合は何もしない
  const handleJump = (e: FormEvent) => {
    e.preventDefault()
    const n = Number.parseInt(jumpValue, 10)
    if (Number.isNaN(n)) return
    onPageChange(() => Math.min(totalPages, Math.max(1, n)))
    setJumpValue('')
  }
  const borderCls = position === 'top' ? 'pb-2 border-b border-slate-800' : 'pt-2 border-t border-slate-800'
  return (
    <nav
      aria-label={position === 'top' ? 'ページ送り（上部）' : 'ページ送り（下部）'}
      className={`flex flex-wrap items-center justify-between gap-x-1 gap-y-2 sm:flex-nowrap sm:gap-2 ${borderCls}`}
    >
      <div className="flex items-center gap-1 sm:gap-2">
        {/* 最初のページへ。狭い画面では記号のみ表示して横幅を節約する */}
        <button
          onClick={() => onPageChange(() => 1)}
          disabled={page === 1}
          aria-label="最初のページへ"
          className={PAGE_BTN_CLS}
        >
          <span aria-hidden="true">«</span>
          <span aria-hidden="true" className="hidden sm:inline">最初</span>
        </button>
        <button
          onClick={() => onPageChange(p => Math.max(1, p - 1))}
          disabled={page === 1}
          className={PAGE_BTN_CLS}
        >
          ← 前へ
        </button>
      </div>
      {/* 中央: 現在位置・件数・ページ番号入力。狭い画面では2段目（全幅）に回して、ボタンの幅を確保する */}
      <div className="order-last flex w-full flex-wrap items-center justify-center gap-x-3 gap-y-1 sm:order-none sm:w-auto sm:flex-nowrap">
        <span className="text-center text-sm text-slate-600 tabular-nums">
          {page} / {totalPages}
          <span className="ml-2 text-slate-700">（{total} 件）</span>
        </span>
        {/* ページ番号の直接入力。Enter または「移動」で確定する */}
        <form onSubmit={handleJump} className="flex items-center gap-1">
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            value={jumpValue}
            onChange={e => setJumpValue(e.target.value.replace(/[^0-9]/g, ''))}
            placeholder="ページ"
            aria-label="ページ番号を入力"
            className="w-14 min-h-9 px-2 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200 text-center tabular-nums placeholder:text-slate-600 focus:outline-none focus:border-slate-500"
          />
          <button
            type="submit"
            disabled={jumpValue === ''}
            aria-label="入力したページへ移動"
            className={PAGE_BTN_CLS}
          >
            移動
          </button>
        </form>
      </div>
      <div className="flex items-center gap-1 sm:gap-2">
        <button
          onClick={() => onPageChange(p => Math.min(totalPages, p + 1))}
          disabled={page === totalPages}
          className={PAGE_BTN_CLS}
        >
          次へ →
        </button>
        {/* 最後のページへ。狭い画面では記号のみ表示する */}
        <button
          onClick={() => onPageChange(() => totalPages)}
          disabled={page === totalPages}
          aria-label="最後のページへ"
          className={PAGE_BTN_CLS}
        >
          <span aria-hidden="true" className="hidden sm:inline">最後</span>
          <span aria-hidden="true">»</span>
        </button>
      </div>
    </nav>
  )
}

// ── 重要度フィルターボタン列 ────────────────────────────────────

export function SeverityFilterButtons({
  severities, active, onSelect, classMap, activeAllClass = 'bg-slate-700 text-white', labels,
}: {
  severities: string[]
  active: string | null
  onSelect: (sev: string) => void
  classMap: Record<string, string>
  activeAllClass?: string
  // 表示用ラベル（例: CODESCANのERROR/WARNING/INFOを日本語表記にする場合）。
  // 未指定時は severities の値をそのまま表示する
  labels?: Record<string, string>
}) {
  return (
    <div role="group" aria-label="深刻度フィルター" className="flex gap-1">
      {severities.map(sev => {
        const isActive = (sev === 'ALL' && active === null) || sev === active
        const cls = isActive
          ? sev === 'ALL'
            ? activeAllClass
            : (classMap[sev] ?? activeAllClass) + ' border'
          : 'bg-slate-800/50 text-slate-500 hover:text-slate-300'
        return (
          <button
            key={sev}
            onClick={() => onSelect(sev)}
            aria-pressed={isActive}
            className={`px-2 py-1 rounded text-xs font-medium transition-colors ${cls}`}
          >
            {labels?.[sev] ?? sev}
          </button>
        )
      })}
    </div>
  )
}

// ── キーワード検索ボックス ────────────────────────────────────

export function SearchBox({
  value, onChange, onClear, placeholder, searchIcon, clearIcon,
}: {
  value: string
  onChange: (value: string) => void
  onClear: () => void
  placeholder: string
  searchIcon: ReactNode
  clearIcon: ReactNode
}) {
  return (
    <div className="flex items-center gap-1.5 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5 flex-1 min-w-[160px]">
      {searchIcon}
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className="bg-transparent text-xs text-slate-300 placeholder:text-slate-600 outline-none w-full"
      />
      {value && (
        <button onClick={onClear} aria-label="検索をクリア" className="text-slate-500 hover:text-slate-300">
          {clearIcon}
        </button>
      )}
    </div>
  )
}

// ── ソートセレクター（更新日 / CVSS） ──────────────────────────

export function SortSelector({
  sortBy, onChange, activeClass,
}: {
  sortBy: 'modified' | 'cvss'
  onChange: (sort: 'modified' | 'cvss') => void
  activeClass: string
}) {
  return (
    <div role="group" aria-label="ソート" className="flex items-center gap-1 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5">
      <span className="text-[10px] text-slate-500 whitespace-nowrap">ソート:</span>
      <button
        onClick={() => onChange('modified')}
        aria-pressed={sortBy === 'modified'}
        className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
          sortBy === 'modified' ? activeClass : 'text-slate-400 hover:text-slate-300'
        }`}
      >
        更新日
      </button>
      <button
        onClick={() => onChange('cvss')}
        aria-pressed={sortBy === 'cvss'}
        className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
          sortBy === 'cvss' ? activeClass : 'text-slate-400 hover:text-slate-300'
        }`}
      >
        CVSS
      </button>
    </div>
  )
}
