import { useState } from 'react'
import { Plus, X } from 'lucide-react'

interface WatchKeywordsProps {
  keywords: string[]
  // キーワードごとの該当件数（取得中・失敗は undefined）
  counts: Record<string, number | undefined>
  // 現在の検索語。キーワードと一致するチップを選択中として見せる
  active: string
  // 「すべて」の件数（期間内の総件数。不明なら null）
  total: number | null
  // キーワードを選ぶ（null = 絞り込みを外す）
  onSelect: (keyword: string | null) => void
  // 追加に失敗したときは理由を返す
  onAdd: (keyword: string) => string | null
  onRemove: (keyword: string) => void
}

// 件数のバッジ。該当ありは赤、0 件は緑（安心の印）、取得中・失敗は「—」
function CountPill({ count }: { count: number | undefined }) {
  if (count === undefined) return <span className="text-slate-600">—</span>
  const cls = count > 0 ? 'bg-red-500/15 text-red-400' : 'bg-emerald-500/15 text-emerald-400'
  return <span className={`px-1.5 rounded-full font-semibold tabular-nums ${cls}`}>{count}</span>
}

// 自分が使っている製品名などのキーワード別に、該当する脆弱性の件数を見せる（KEV・OSV・JVN 共通）。
// チップを押すと、そのキーワードで一覧を絞り込む
export function WatchKeywords({
  keywords, counts, active, total, onSelect, onAdd, onRemove,
}: WatchKeywordsProps) {
  const [draft, setDraft] = useState('')
  const [error, setError] = useState<string | null>(null)
  const activeKey = active.trim().toLowerCase()

  function submit() {
    const result = onAdd(draft)
    setError(result)
    if (result === null) setDraft('')
  }

  const chipBase = 'flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs transition-colors'
  const chipCls = (on: boolean) => (on
    ? `${chipBase} border-violet-500/60 bg-violet-500/10 text-slate-100`
    : `${chipBase} border-slate-700 bg-slate-800/60 text-slate-300 hover:bg-slate-800`)

  return (
    <div className="flex flex-col gap-2">
      <div role="group" aria-label="自分のスタックのキーワード" className="flex flex-wrap items-center gap-1.5">
        <button onClick={() => onSelect(null)} aria-pressed={activeKey === ''} className={chipCls(activeKey === '')}>
          すべて
          {total !== null && <span className="text-slate-500 tabular-nums">{total}</span>}
        </button>

        {keywords.map(keyword => {
          const on = activeKey === keyword.toLowerCase()
          return (
            <span key={keyword} className={`${chipCls(on)} !pr-1`}>
              <button onClick={() => onSelect(keyword)} aria-pressed={on} className="flex items-center gap-1.5">
                {keyword}
                <CountPill count={counts[keyword]} />
              </button>
              <button
                onClick={() => onRemove(keyword)}
                aria-label={`${keyword}を削除`}
                className="p-0.5 rounded text-slate-500 hover:text-slate-200"
              >
                <X size={10} />
              </button>
            </span>
          )
        })}

        <form
          onSubmit={e => { e.preventDefault(); submit() }}
          className="flex items-center gap-1 rounded-lg border border-dashed border-slate-700 px-2 py-1"
        >
          <input
            value={draft}
            onChange={e => setDraft(e.target.value)}
            placeholder="製品名を追加"
            aria-label="キーワードを追加"
            className="bg-transparent text-xs text-slate-300 placeholder:text-slate-600 outline-none w-24"
          />
          <button type="submit" aria-label="キーワードを追加する" className="text-slate-500 hover:text-slate-200">
            <Plus size={12} />
          </button>
        </form>
      </div>

      {error && <p role="alert" className="text-[11px] text-amber-400">{error}</p>}
      {keywords.length === 0 && (
        <p className="text-[11px] text-slate-600">
          使っている製品名（例: Python・nginx）を追加すると、該当する脆弱性の件数がここに出ます。
        </p>
      )}
    </div>
  )
}
