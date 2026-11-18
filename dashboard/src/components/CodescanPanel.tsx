import { ScanSearch } from 'lucide-react'
import {
  TableLoadingSkeleton, EmptyState, Pagination, SeverityFilterButtons,
} from './shared/VulnPanelParts'
import { RepoBarChart } from './codescan/RepoBarChart'
import { CountBadge } from './codescan/CountBadge'
import { useCodescanData } from './codescan/useCodescanData'
import { OperatingFilter } from './shared/OperatingFilter'
import { ExceptedToggle } from './shared/ExceptedToggle'
import { ActionSummary } from './shared/ActionSummary'
import { CollapsibleSection } from './shared/CollapsibleSection'
import { RepoRail } from './shared/RepoRail'
import { repoShortName } from './shared/repoName'
import {
  CODESCAN_TEXT as T, SEVERITIES, SEVERITY_CLS, SEVERITY_LABELS,
} from './codescan/codescanPanelConfig'
import { CodescanHeader, CodescanTable, ResolvedFilter } from './codescan/CodescanSections'

// authToken 指定時（GitHubログイン経由）は、サーバー側で require_api_key_or_session
// によりログイン必須になる（Issue #219）。DepscanPanel と同じ props パターン。
export function CodescanPanel({ authToken }: { authToken?: string } = {}) {
  const {
    severity, resolved, showExcepted, operating, page, setPage,
    result, stats, loading, statsLoading,
    load, handleSev, handleOperating, handleResolvedToggle, toggleShowExcepted,
    selectedRepo, handleRepo, totalPages, errorCount,
  } = useCodescanData(authToken)

  // 例外（受容・影響なしなど）にした未解決の件数。一覧には出るが、「対応が必要」の件数には含めない
  const exceptedTotal = stats?.excepted_total ?? 0
  // 現在の絞り込み条件で取り直す（再読み込み・例外の変更後に使う）
  const reload = () => load(severity, resolved, page, operating, selectedRepo, showExcepted)

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">
      <CodescanHeader busy={loading || statsLoading} onReload={reload} />

      <p className="text-[11px] text-slate-600 leading-relaxed">{T.note}</p>

      {/* グラフ。最初は表示し、見出しを押すと閉じられる */}
      <CollapsibleSection summary={T.charts}>
        <RepoBarChart stats={stats} loading={statsLoading} />
      </CollapsibleSection>

      {/* 運用状態フィルター + 重要度フィルター + 解決状態フィルター + 例外の表示切替 */}
      <div className="flex flex-wrap items-center gap-3">
        <OperatingFilter value={operating} onChange={handleOperating} />
        <SeverityFilterButtons
          severities={SEVERITIES}
          active={severity}
          onSelect={handleSev}
          classMap={SEVERITY_CLS}
          labels={SEVERITY_LABELS}
        />
        <ResolvedFilter resolved={resolved} onChange={handleResolvedToggle} />
        <ExceptedToggle active={showExcepted} onToggle={toggleShowExcepted} count={exceptedTotal} />
      </div>

      {/* いま対応が必要な件数（未解決の重大＝ERROR） */}
      <ActionSummary
        count={errorCount}
        criteria={T.actionCriteria}
        total={stats?.total ?? null}
        loading={statsLoading && !stats}
      />

      {/* 例外は、「対応が必要」の件数には含めない。一覧は、初期は例外を除き、切り替えで含める。
          グラフと左のアプリ一覧では、灰色の「例外」として併記する。この違いを明記する */}
      {exceptedTotal > 0 && (
        <p className="text-xs text-slate-500" data-testid="excepted-note">
          {T.excepted(exceptedTotal, showExcepted)}
        </p>
      )}

      {/* 左: アプリ一覧／右: 選んだアプリの脆弱性 */}
      <div className="flex flex-col md:flex-row gap-4">
        <RepoRail
          selected={selectedRepo}
          onSelect={handleRepo}
          allBadge={<CountBadge count={stats?.total ?? 0} excepted={exceptedTotal} muted />}
          items={(stats?.repos ?? []).map(r => ({
            key: r.repo_full_name,
            label: repoShortName(r.repo_full_name),
            badge: <CountBadge count={r.count} excepted={r.excepted_count} />,
          }))}
        />

        <div className="flex-1 min-w-0 flex flex-col gap-3">
          {loading ? (
            <TableLoadingSkeleton columnWidths={['w-16', 'w-12', 'w-32', 'w-40', 'flex-1']} />
          ) : result && result.total === 0 ? (
            <EmptyState icon={<ScanSearch size={28} />} message={
              exceptedTotal > 0 && !showExcepted && resolved === false
                ? T.emptyHidden(exceptedTotal)
                : T.empty
            } />
          ) : result && (
            <>
              <Pagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} position="top" />
              <CodescanTable
                result={result} selectedRepo={selectedRepo}
                authToken={authToken} onExceptionChanged={reload}
              />
              <Pagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} />
            </>
          )}
        </div>
      </div>
    </div>
  )
}
