import { useCallback, useEffect, useState } from 'react'
import {
  fetchCodescanList, fetchCodescanStats,
  type CodescanListResponse, type CodescanStatsResponse, type OperatingStatus,
} from '../../api/client'

const PER_PAGE = 30

// CodescanPanel のデータ取得・フィルタ状態管理ロジック。OsvPanel の useOsvData と
// 同じ構成パターン（Separation of Concerns: UIレンダリングとロジックを分離）。
//
// authToken 指定時（GitHubログイン経由、Issue #219）は X-API-KEY の代わりに
// Authorization: Bearer ヘッダーを送る（DepscanPanel の useDepscanData と同じパターン）。
export function useCodescanData(authToken?: string) {
  const [severity, setSeverity] = useState<string | null>(null)
  const [resolved, setResolved] = useState<boolean | null>(false)
  // 例外（受容・影響なし・誤検知）にした検知を一覧に含めるか。初期は含めない（対応が必要なものだけを見せる）
  const [showExcepted, setShowExcepted] = useState(false)
  // 初期表示は運用中のみ（運用停止中のアプリの脆弱性に埋もれず、運用中のものを見やすくするため）
  const [operating, setOperating] = useState<OperatingStatus>('active')
  // 左のアプリ一覧で選んでいるリポジトリ（null = すべてのアプリ）。一覧APIの repo で絞り込む
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<CodescanListResponse | null>(null)
  const [stats, setStats] = useState<CodescanStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [statsLoading, setStatsLoading] = useState(true)

  // 一覧（フィルタ・ページ）とグラフ用の統計は独立して取得する。統計はページ送り
  // では変化しないため、ページ送りのたびにグラフが読み込み中表示に戻るのを防ぐ
  const loadList = useCallback(async (
    sev: string | null, res: boolean | null, p: number, op: OperatingStatus, repo: string | null,
    withExcepted: boolean,
  ) => {
    setLoading(true)
    try {
      const list = await fetchCodescanList({
        severity: sev, resolved: res, page: p, perPage: PER_PAGE, operating: op, repo,
        includeExcepted: withExcepted, authToken,
      })
      setResult(list)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う。他パネルと同じ方針）
    } finally {
      setLoading(false)
    }
  }, [authToken])

  const loadStats = useCallback(async (op: OperatingStatus) => {
    setStatsLoading(true)
    try {
      const st = await fetchCodescanStats(authToken, op)
      setStats(st)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う。他パネルと同じ方針）
    } finally {
      setStatsLoading(false)
    }
  }, [authToken])

  const load = useCallback((
    sev: string | null, res: boolean | null, p: number, op: OperatingStatus, repo: string | null,
    withExcepted: boolean,
  ) => {
    loadList(sev, res, p, op, repo, withExcepted)
    loadStats(op)
  }, [loadList, loadStats])

  useEffect(() => {
    loadList(severity, resolved, page, operating, selectedRepo, showExcepted)
  }, [loadList, severity, resolved, page, operating, selectedRepo, showExcepted])

  useEffect(() => {
    loadStats(operating)
  }, [loadStats, operating])

  function handleSev(sev: string) {
    setSeverity(sev === 'ALL' ? null : sev)
    setPage(1)
  }

  function handleOperating(op: OperatingStatus) {
    setOperating(op)
    // 運用状態を切り替えると、選んでいたアプリが一覧に無いことがあるため、選択を戻す
    setSelectedRepo(null)
    setPage(1)
  }

  function handleRepo(repo: string | null) {
    setSelectedRepo(repo)
    setPage(1)
  }

  function handleResolvedToggle(value: boolean | null) {
    setResolved(value)
    setPage(1)
  }

  function toggleShowExcepted() {
    setShowExcepted(v => !v)
    setPage(1)
  }

  const totalPages = result ? Math.ceil(result.total / PER_PAGE) : 0
  const errorCount = stats?.severities.find(s => s.severity === 'ERROR')?.count ?? 0

  return {
    severity, resolved, showExcepted, page, setPage,
    result, stats, loading, statsLoading,
    operating, load, handleSev, handleOperating, handleResolvedToggle, toggleShowExcepted,
    selectedRepo, handleRepo, totalPages, errorCount,
  }
}
