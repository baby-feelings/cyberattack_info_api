import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  fetchAllDepscanFindings, fetchDepscanStats, fetchCrawlerLogs,
  type DependencyFindingOut, type DepscanStatsResponse,
} from '../../api/client'
import {
  ownerOf, groupFindings, groupBestSeverityRank, groupLatestDetectedAt,
} from './grouping'

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
    own: string | null, sev: string | null, resolved: boolean,
  ) => {
    setLoading(true)
    try {
      const [all, st] = await Promise.all([
        fetchAllDepscanFindings({
          owner: own, severity: sev, resolved: resolved ? null : false, authToken,
        }),
        fetchDepscanStats(authToken),
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
    load(owner, severity, showResolved)
  }, [load, owner, severity, showResolved])

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

  // パッケージ×バージョン単位に集約し、重大度が高い順・検知が新しい順に並べる
  const groups = useMemo(() => {
    const g = groupFindings(findings)
    g.sort((a, b) => {
      const r = groupBestSeverityRank(a) - groupBestSeverityRank(b)
      if (r !== 0) return r
      return groupLatestDetectedAt(b).localeCompare(groupLatestDetectedAt(a))
    })
    return g
  }, [findings])

  function handleOwner(o: string) {
    setOwner(o === 'ALL' ? null : o)
    setPage(1)
  }

  function handleSev(sev: string) {
    setSeverity(sev === 'ALL' ? null : sev)
    setPage(1)
  }

  function toggleShowResolved() {
    setShowResolved(v => !v)
    setPage(1)
  }

  const totalPages = Math.ceil(groups.length / PER_PAGE)
  const pageGroups = groups.slice((page - 1) * PER_PAGE, page * PER_PAGE)

  const critCount = stats?.severities.find(s => s.severity === 'CRITICAL')?.count ?? 0
  const highCount = stats?.severities.find(s => s.severity === 'HIGH')?.count ?? 0

  return {
    owner, severity, showResolved, page, setPage,
    findings, stats, loading, newDataAvailable,
    load, handleOwner, handleSev, toggleShowResolved,
    owners, groups, totalPages, pageGroups, critCount, highCount,
  }
}
