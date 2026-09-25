import { useCallback, useEffect, useState } from 'react'
import {
  fetchCodescanList, fetchCodescanStats,
  type CodescanListResponse, type CodescanStatsResponse,
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
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<CodescanListResponse | null>(null)
  const [stats, setStats] = useState<CodescanStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [statsLoading, setStatsLoading] = useState(true)

  // 一覧（フィルタ・ページ）とグラフ用の統計は独立して取得する。統計はページ送り
  // では変化しないため、ページ送りのたびにグラフが読み込み中表示に戻るのを防ぐ
  const loadList = useCallback(async (
    sev: string | null, res: boolean | null, p: number,
  ) => {
    setLoading(true)
    try {
      const list = await fetchCodescanList({ severity: sev, resolved: res, page: p, perPage: PER_PAGE, authToken })
      setResult(list)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う。他パネルと同じ方針）
    } finally {
      setLoading(false)
    }
  }, [authToken])

  const loadStats = useCallback(async () => {
    setStatsLoading(true)
    try {
      const st = await fetchCodescanStats(authToken)
      setStats(st)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う。他パネルと同じ方針）
    } finally {
      setStatsLoading(false)
    }
  }, [authToken])

  const load = useCallback((
    sev: string | null, res: boolean | null, p: number,
  ) => {
    loadList(sev, res, p)
    loadStats()
  }, [loadList, loadStats])

  useEffect(() => {
    loadList(severity, resolved, page)
  }, [loadList, severity, resolved, page])

  useEffect(() => {
    loadStats()
  }, [loadStats])

  function handleSev(sev: string) {
    setSeverity(sev === 'ALL' ? null : sev)
    setPage(1)
  }

  function handleResolvedToggle(value: boolean | null) {
    setResolved(value)
    setPage(1)
  }

  const totalPages = result ? Math.ceil(result.total / PER_PAGE) : 0
  const errorCount = stats?.severities.find(s => s.severity === 'ERROR')?.count ?? 0

  return {
    severity, resolved, page, setPage,
    result, stats, loading, statsLoading,
    load, handleSev, handleResolvedToggle,
    totalPages, errorCount,
  }
}
