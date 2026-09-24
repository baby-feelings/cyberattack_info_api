import { useCallback, useEffect, useState } from 'react'
import {
  fetchCodescanList, fetchCodescanStats,
  type CodescanListResponse, type CodescanStatsResponse,
} from '../../api/client'

const PER_PAGE = 30

// CodescanPanel のデータ取得・フィルタ状態管理ロジック。OsvPanel の useOsvData と
// 同じ構成パターン（Separation of Concerns: UIレンダリングとロジックを分離）。
export function useCodescanData() {
  const [severity, setSeverity] = useState<string | null>(null)
  const [resolved, setResolved] = useState<boolean | null>(false)
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<CodescanListResponse | null>(null)
  const [stats, setStats] = useState<CodescanStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async (
    sev: string | null, res: boolean | null, p: number,
  ) => {
    setLoading(true)
    try {
      const [list, st] = await Promise.all([
        fetchCodescanList({ severity: sev, resolved: res, page: p, perPage: PER_PAGE }),
        fetchCodescanStats(),
      ])
      setResult(list)
      setStats(st)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う。他パネルと同じ方針）
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(severity, resolved, page)
  }, [load, severity, resolved, page])

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
    result, stats, loading,
    load, handleSev, handleResolvedToggle,
    totalPages, errorCount,
  }
}
