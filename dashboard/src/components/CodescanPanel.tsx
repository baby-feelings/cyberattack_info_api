import { RefreshCw, ScanSearch } from 'lucide-react'
import {
  TableLoadingSkeleton, EmptyState, Pagination, SeverityFilterButtons,
} from './shared/VulnPanelParts'
import { CodescanRow } from './codescan/CodescanRow'
import { RepoBarChart } from './codescan/RepoBarChart'
import { useCodescanData } from './codescan/useCodescanData'
import { OperatingFilter } from './shared/OperatingFilter'
import { ActionSummary } from './shared/ActionSummary'
import { CollapsibleSection } from './shared/CollapsibleSection'
import { RepoRail } from './shared/RepoRail'
import { repoShortName } from './shared/repoName'

const SEVERITY_CLS: Record<string, string> = {
  ERROR: 'bg-red-500/15 text-red-400 border-red-500/30',
  WARNING: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  INFO: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

const SEVERITIES = ['ALL', 'ERROR', 'WARNING', 'INFO']

// 重要度の表示ラベル。ERRORはシステムエラーと紛らわしいため日本語表記にする
const SEVERITY_LABELS: Record<string, string> = {
  ERROR: '重大',
  WARNING: '警告',
  INFO: '情報',
}

// authToken 指定時（GitHubログイン経由）は、サーバー側で require_api_key_or_session
// によりログイン必須になる（Issue #219）。DepscanPanel と同じ props パターン。
export function CodescanPanel({ authToken }: { authToken?: string } = {}) {
  const {
    severity, resolved, operating, page, setPage,
    result, stats, loading, statsLoading,
    load, handleSev, handleOperating, handleResolvedToggle,
    selectedRepo, handleRepo, totalPages, errorCount,
  } = useCodescanData(authToken)

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">

      {/* ヘッダー */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ScanSearch size={16} className="text-slate-400" />
            <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
              CODESCAN（Semgrep + Gitleaks + Zizmor + インフラ設定）
            </span>
          </div>
          <button
            onClick={() => load(severity, resolved, page, operating, selectedRepo)}
            disabled={loading || statsLoading}
            className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
            title="再読み込み"
          >
            <RefreshCw size={13} className={loading || statsLoading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* 注記: CVSSはベストエフォート推定であることを明記（Issue #203の要件） */}
      <p className="text-[11px] text-slate-600 leading-relaxed">
        Semgrep（コードパターン診断）・Gitleaks（ハードコードされたシークレット検知）・
        Zizmor（GitHub Actionsのワークフロー設定の診断。未固定のアクション・過剰な権限など）の
        インフラ設定（FirebaseのルールやDockerfile・docker-composeの不備）の4つで検知します。
        CVSSスコアは検知結果（重要度・CWE）からのベストエフォート推定値であり、正式なCVSS評価に
        代わるものではありません（Zizmor・インフラ設定の検知にはCVSSが付きません）。
        7.0以上は赤バッジで強調表示します。
      </p>

      {/* グラフ。最初は表示し、見出しを押すと閉じられる */}
      <CollapsibleSection summary="グラフ（リポジトリ別）">
        <RepoBarChart stats={stats} loading={statsLoading} />
      </CollapsibleSection>

      {/* 運用状態フィルター + 重要度フィルター + 解決状態フィルター */}
      <div className="flex flex-wrap items-center gap-3">
        <OperatingFilter value={operating} onChange={handleOperating} />
        <SeverityFilterButtons
          severities={SEVERITIES}
          active={severity}
          onSelect={handleSev}
          classMap={SEVERITY_CLS}
          labels={SEVERITY_LABELS}
        />
        <div role="group" aria-label="状態フィルター" className="flex items-center gap-1 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5">
          <span className="text-[10px] text-slate-500 whitespace-nowrap">状態:</span>
          {([
            { label: '未解決', value: false as boolean | null },
            { label: '解決済み', value: true as boolean | null },
            { label: '全件', value: null as boolean | null },
          ]).map(opt => (
            <button
              key={opt.label}
              onClick={() => handleResolvedToggle(opt.value)}
              aria-pressed={resolved === opt.value}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                resolved === opt.value
                  ? 'bg-rose-600 text-white'
                  : 'text-slate-400 hover:text-slate-300'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* いま対応が必要な件数（未解決の重大＝ERROR） */}
      <ActionSummary
        count={errorCount}
        criteria="重大"
        total={stats?.total ?? null}
        loading={statsLoading && !stats}
      />

      {/* 左: アプリ一覧／右: 選んだアプリの脆弱性 */}
      <div className="flex flex-col md:flex-row gap-4">
        <RepoRail
          selected={selectedRepo}
          onSelect={handleRepo}
          allBadge={<span className="text-slate-500 tabular-nums">{stats?.total ?? 0}</span>}
          items={(stats?.repos ?? []).map(r => ({
            key: r.repo_full_name,
            label: repoShortName(r.repo_full_name),
            badge: <span className="text-slate-300 tabular-nums">{r.count}</span>,
          }))}
        />

        <div className="flex-1 min-w-0 flex flex-col gap-3">
          {/* ローディング */}
          {loading ? (
            <TableLoadingSkeleton columnWidths={['w-16', 'w-12', 'w-32', 'w-40', 'flex-1']} />

          /* データなし */
          ) : result && result.total === 0 ? (
            <EmptyState icon={<ScanSearch size={28} />} message="該当するコード脆弱性はありません" />

          /* テーブル */
          ) : result && (
            <>
              <Pagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} position="top" />

              <div className="overflow-x-auto -mx-1 px-1">
                <table aria-label="コード脆弱性一覧" className="w-full text-sm min-w-[560px]">
                  <thead>
                    <tr className="border-b border-slate-800">
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-20">重要度</th>
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-16">CVSS</th>
                      {!selectedRepo && (
                        <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-40">リポジトリ</th>
                      )}
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">ファイル:行</th>
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">ルール</th>
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">検知日</th>
                      <th className="w-5" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {result.data.map((item, i) => (
                      <CodescanRow
                        key={`${item.repo_full_name}-${item.file_path}-${item.rule_id}-${item.line_start}-${i}`}
                        item={item}
                        showRepo={!selectedRepo}
                        authToken={authToken}
                        onExceptionChanged={() => load(severity, resolved, page, operating, selectedRepo)}
                      />
                    ))}
                  </tbody>
                </table>
              </div>

              <Pagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} />
            </>
          )}
        </div>
      </div>

    </div>
  )
}
