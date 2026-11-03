import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  fetchAllDepscanFindings, fetchDepscanStats, fetchCrawlerLogs,
  type DependencyFindingOut, type DepscanStatsResponse, type OperatingStatus,
} from '../../api/client'
import {
  ownerOf, groupFindings, type FindingGroup, groupBestSeverityRank, groupLatestDetectedAt,
} from './grouping'
import { summarizeRepos } from './repoSummary'
import type { DepscanSort } from './DepscanSortSelector'

const PER_PAGE = 30
// 新しいDEPSCANクロールが完了していないかを確認する間隔（ミリ秒）
const UPDATE_CHECK_INTERVAL_MS = 120000

// DepscanPanel のデータ取得・ポーリング・フィルタ状態管理ロジックを切り出したカスタムフック。
// DepscanPanel 本体は UI レンダリングに専念させる（Separation of Concerns）。
// ポーリング間隔・フィルタ条件・表示内容（挙動）はDepscanPanelから移植前と変更していない。
//
// authToken 指定時（GitHubログイン経由）は、サーバー側でログインユーザー本人が
// 所有するリポジトリのみに強制的に絞り込まれる（オーナーフィルターは実質不要になる）
export function useDepscanData(authToken?: string) {
  const [owner, setOwner] = useState<string | null>(null)
  const [severity, setSeverity] = useState<string | null>(null)
  const [showResolved, setShowResolved] = useState(false)
  // 例外（受容・影響なし・誤検知）にした検知を含めるか。初期は含めない（対応が必要なものだけを見せる）
  const [showExcepted, setShowExcepted] = useState(false)
  // 初期表示は運用中のみ（運用停止中のアプリの脆弱性に埋もれず、運用中のものを見やすくするため）
  const [operating, setOperating] = useState<OperatingStatus>('active')
  // 左のアプリ一覧で選んでいるリポジトリ（null = すべてのアプリ）。絞り込みは取得済みの結果に対して行う
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null)
  // 並び順。既定は重要度順。検知日順のときは、検知日ごとの区切りを出す
  const [sortBy, setSortBy] = useState<DepscanSort>('severity')
  const [page, setPage] = useState(1)
  const [findings, setFindings] = useState<DependencyFindingOut[]>([])
  const [stats, setStats] = useState<DepscanStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [newDataAvailable, setNewDataAvailable] = useState(false)
  // 表示中データの基準となる、最後に確認した最新クロールログID
  // （ポーリング用 effect から常に最新値を読めるよう state ではなく ref で持つ）
  const lastSeenLogIdRef = useRef<number | null>(null)

  // 直近成功した DEPSCAN クロールログの ID を取得する（取得失敗時は null）
  const fetchLatestLogId = useCallback(async (): Promise<number | null> => {
    try {
      const logs = await fetchCrawlerLogs({ crawlerType: 'DEPSCAN', status: 'success', limit: 1 })
      return logs[0]?.id ?? null
    } catch {
      return null
    }
  }, [])

  const load = useCallback(async (
    own: string | null, sev: string | null, resolved: boolean, op: OperatingStatus,
    withExcepted: boolean,
  ) => {
    setLoading(true)
    try {
      const [all, st] = await Promise.all([
        fetchAllDepscanFindings({
          owner: own, severity: sev, resolved: resolved ? null : false, operating: op,
          includeExcepted: withExcepted, authToken,
        }),
        fetchDepscanStats(authToken, op),
      ])
      setFindings(all)
      setStats(st)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setLoading(false)
    }
    // 表示したデータの基準として、この時点の最新クロールログIDを記録する
    lastSeenLogIdRef.current = await fetchLatestLogId()
    setNewDataAvailable(false)
  }, [authToken, fetchLatestLogId])

  useEffect(() => {
    load(owner, severity, showResolved, operating, showExcepted)
  }, [load, owner, severity, showResolved, operating, showExcepted])

  // 定期的に新しい DEPSCAN クロールが完了していないか確認し、あればバナーで通知する
  // （バックグラウンドで自動更新はせず、ユーザーが更新ボタンを押すまで表示は変えない）
  useEffect(() => {
    const interval = setInterval(async () => {
      const latestId = await fetchLatestLogId()
      if (
        latestId !== null
        && lastSeenLogIdRef.current !== null
        && latestId !== lastSeenLogIdRef.current
      ) {
        setNewDataAvailable(true)
      }
    }, UPDATE_CHECK_INTERVAL_MS)
    return () => clearInterval(interval)
  }, [fetchLatestLogId])

  // オーナー一覧は stats.repos（未解決分の全リポジトリ）から動的に導出する。
  // 表示されるのは DB に保存済み＝DEPSCAN が GITHUB_TOKEN の権限内で実際に
  // スキャンしたリポジトリのみ（現状は GITHUB_USERNAME=baby-feelings が
  // 所有するリポジトリだけ）。運用者が意図的に監視対象アカウントを増やした
  // 場合のみボタンが増える設計で、無関係な第三者のデータが混ざることはない。
  const owners = useMemo(() => {
    const set = new Set((stats?.repos ?? []).map(r => ownerOf(r.repo_full_name)))
    return Array.from(set).sort()
  }, [stats])

  // 左のアプリ一覧（対応が必要なアプリが上）。絞り込み条件の変更で選択中のアプリが一覧から
  // 消えた場合は、選択を「すべてのアプリ」に戻す
  const repos = useMemo(() => summarizeRepos(findings), [findings])
  const activeRepo = repos.some(r => r.repo === selectedRepo) ? selectedRepo : null

  // パッケージ×バージョン単位に集約する。重要度順は「重大度が高い順・検知が新しい順」、
  // 検知日順は「検知が新しい順（同じ日は重大度が高い順）」
  const groups = useMemo(() => {
    const target = activeRepo ? findings.filter(f => f.repo_full_name === activeRepo) : findings
    const g = groupFindings(target)
    const byDate = (a: FindingGroup, b: FindingGroup) =>
      groupLatestDetectedAt(b).localeCompare(groupLatestDetectedAt(a))
    const bySeverity = (a: FindingGroup, b: FindingGroup) =>
      groupBestSeverityRank(a) - groupBestSeverityRank(b)
    g.sort(sortBy === 'date'
      ? (a, b) => byDate(a, b) || bySeverity(a, b)
      : (a, b) => bySeverity(a, b) || byDate(a, b))
    return g
  }, [findings, activeRepo, sortBy])

  function handleRepo(repo: string | null) {
    setSelectedRepo(repo)
    setPage(1)
  }

  function handleOwner(o: string) {
    setOwner(o === 'ALL' ? null : o)
    setPage(1)
  }

  function handleSev(sev: string) {
    setSeverity(sev === 'ALL' ? null : sev)
    setPage(1)
  }

  function handleOperating(op: OperatingStatus) {
    setOperating(op)
    setPage(1)
  }

  function handleSort(sort: DepscanSort) {
    setSortBy(sort)
    setPage(1)
  }

  function toggleShowResolved() {
    setShowResolved(v => !v)
    setPage(1)
  }

  function toggleShowExcepted() {
    setShowExcepted(v => !v)
    setPage(1)
  }

  const totalPages = Math.ceil(groups.length / PER_PAGE)
  const pageGroups = groups.slice((page - 1) * PER_PAGE, page * PER_PAGE)

  const critCount = stats?.severities.find(s => s.severity === 'CRITICAL')?.count ?? 0
  const highCount = stats?.severities.find(s => s.severity === 'HIGH')?.count ?? 0

  return {
    owner, severity, showResolved, showExcepted, operating, sortBy, handleSort, page, setPage,
    findings, stats, loading, newDataAvailable,
    load, handleOwner, handleSev, handleOperating, toggleShowResolved, toggleShowExcepted,
    owners, groups, totalPages, pageGroups, critCount, highCount,
    repos, activeRepo, handleRepo,
  }
}
