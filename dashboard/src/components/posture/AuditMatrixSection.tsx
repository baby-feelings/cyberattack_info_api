import { Fragment, useId, useState } from 'react'
import { SCREEN_FETCH_SOURCE } from '../freshness/freshnessConfig'
import type { AuditMatrix } from './model/AuditMatrix'
import { AUDIT_STATUS_VIEW, POSTURE_TEXT } from './postureConfig'
import { PostureSection } from './PostureSection'
import type { Source } from './usePostureData'

// 押して開いているセル（リポジトリ × 点検項目）
interface SelectedCell { repo: string; key: string }

// 「リポジトリ × 点検項目」の表。設定の抜けを、リポジトリをまたいで見つけるための、この画面の見せ場。
export function AuditMatrixSection({ source, onRetry }: { source: Source<AuditMatrix>; onRetry: () => void }) {
  return (
    <PostureSection
      title={POSTURE_TEXT.audit.title}
      crawlerType={SCREEN_FETCH_SOURCE.postureAudit}
      source={source}
      onRetry={onRetry}
    >
      {(matrix) => <AuditMatrixView matrix={matrix} />}
    </PostureSection>
  )
}

function AuditMatrixView({ matrix }: { matrix: AuditMatrix }) {
  const detailId = useId()
  // 初期は、改善が必要なものだけ（運用中のアプリで、直すべきところを先に見せる）
  const [onlyIssues, setOnlyIssues] = useState(true)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<SelectedCell | null>(null)

  // 点検の結果が、1件もないときは、表も絞り込みも出さない
  if (matrix.rows().length === 0) {
    return <p className="text-sm text-slate-400">{POSTURE_TEXT.audit.empty}</p>
  }

  const columns = matrix.columns()
  const rows = matrix.rows({ onlyIssues, query })
  const selectedCheck = selected
    ? matrix.rows({ query: selected.repo }).find((audit) => audit.repo === selected.repo)?.checkOf(selected.key)
    : undefined

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-4 text-sm">
        <label className="flex items-center gap-2 text-slate-300">
          <input
            type="checkbox"
            checked={onlyIssues}
            onChange={(e) => setOnlyIssues(e.target.checked)}
          />
          {POSTURE_TEXT.audit.onlyIssues}
        </label>
        <input
          type="search"
          aria-label={POSTURE_TEXT.audit.search}
          placeholder={POSTURE_TEXT.audit.search}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="rounded-lg bg-slate-800 border border-slate-700 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-500"
        />
        <span className="text-xs text-slate-500">{POSTURE_TEXT.audit.legend}</span>
      </div>

      {rows.length === 0 ? (
        <p className="text-sm text-slate-400">
          {onlyIssues && !query.trim() ? POSTURE_TEXT.audit.noIssues : POSTURE_TEXT.audit.noMatch}
        </p>
      ) : (
        // スマホ幅では、表を横にスクロールし、リポジトリ名の列を固定する
        <div className="relative overflow-x-auto">
          <table aria-label={POSTURE_TEXT.audit.title} className="min-w-full text-sm border-separate border-spacing-0">
            <thead>
              <tr>
                <th scope="col" className="sticky left-0 z-10 bg-slate-900 px-3 py-2 text-left text-xs font-medium text-slate-400 border-b border-slate-800">
                  {POSTURE_TEXT.audit.repoColumn}
                </th>
                {columns.map((column) => (
                  <th key={column.key} scope="col" className="px-3 py-2 text-left text-xs font-medium text-slate-400 border-b border-slate-800 whitespace-nowrap">
                    {column.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((audit) => (
                <Fragment key={audit.repo}>
                <tr>
                  <th scope="row" className="sticky left-0 z-10 bg-slate-900 px-3 py-2 text-left font-medium text-slate-200 whitespace-nowrap border-b border-slate-800">
                    {audit.repo}
                  </th>
                  {columns.map((column) => {
                    const check = audit.checkOf(column.key)
                    // この項目が点検されていないリポジトリは「取得不可」（押せない）
                    const view = AUDIT_STATUS_VIEW[check?.status.kind ?? 'unavailable']
                    const cls = `inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-medium ${view.cls}`
                    const isOpen = selected?.repo === audit.repo && selected.key === column.key
                    return (
                      <td key={column.key} className="px-3 py-2 border-b border-slate-800">
                        {check ? (
                          <button
                            type="button"
                            aria-label={`${audit.repo} ${check.label} ${view.label}`}
                            aria-expanded={isOpen}
                            aria-controls={isOpen ? detailId : undefined}
                            onClick={() => setSelected(isOpen ? null : { repo: audit.repo, key: column.key })}
                            className={`${cls} hover:brightness-125 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400`}
                          >
                            <span aria-hidden="true">{view.glyph}</span>
                            <span>{view.label}</span>
                          </button>
                        ) : (
                          <span role="img" aria-label={`${audit.repo} ${column.label} ${view.label}`} className={cls}>
                            <span aria-hidden="true">{view.glyph}</span>
                            <span aria-hidden="true">{view.label}</span>
                          </span>
                        )}
                      </td>
                    )
                  })}
                </tr>
                {/* 押した項目の詳細と直し方は、その行のすぐ下に出す（表の下まで目を動かさなくてよい） */}
                {selected?.repo === audit.repo && selectedCheck && (
                  <tr>
                    <td colSpan={columns.length + 1} className="p-0 border-b border-slate-800">
                      {/* 横にスクロールしても、詳細は見えている範囲に固定する */}
                      <div
                        id={detailId}
                        role="region"
                        aria-label={`${selected.repo} ${selectedCheck.label}`}
                        className="sticky left-0 w-[calc(100vw-3rem)] max-w-3xl m-2 rounded-lg border border-slate-700 bg-slate-800/60 p-3 text-sm text-slate-300 flex flex-col gap-1"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <p className="font-medium text-slate-200">
                            {selectedCheck.label}: {AUDIT_STATUS_VIEW[selectedCheck.status.kind].label}
                          </p>
                          <button
                            type="button"
                            onClick={() => setSelected(null)}
                            className="text-xs text-slate-400 hover:text-slate-200 shrink-0"
                          >
                            {POSTURE_TEXT.audit.close}
                          </button>
                        </div>
                        {selectedCheck.detail && <p><span className="text-slate-500">{POSTURE_TEXT.audit.detail}: </span>{selectedCheck.detail}</p>}
                        {selectedCheck.fix && <p><span className="text-slate-500">{POSTURE_TEXT.audit.fix}: </span>{selectedCheck.fix}</p>}
                      </div>
                    </td>
                  </tr>
                )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

    </div>
  )
}
