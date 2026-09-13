import { useCallback, useEffect, useState } from 'react'
import {
  fetchOsvList, fetchOsvStats,
  type OsvListResponse, type OsvStatsResponse,
} from '../../api/client'

const PER_PAGE = 30

// OsvPanel のデータ取得・フィルタ状態管理ロジックを切り出したカスタムフック。
// OsvPanel本体はUIレンダリングに専念させる（Separation of Concerns）。
// フィルタ条件・表示内容（挙動）はOsvPanelから移植前と変更していない。
export function useOsvData() {
  const [ecosystem, setEcosystem] = useState<string | null>(null)
  const [severity, setSeverity] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState<'modified' | 'cvss'>('modified')
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<OsvListResponse | null>(null)
  const [stats, setStats] = useState<OsvStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async (
    eco: string | null, sev: string | null, q: string,
    p: number, sort: 'modified' | 'cvss',
  ) => {
    setLoading(true)
    try {
      const [list, st] = await Promise.all([
        fetchOsvList({ ecosystem: eco, severity: sev, search: q, page: p, perPage: PER_PAGE, sortBy: sort }),
        fetchOsvStats(180),
      ])
      setResult(list)
      setStats(st)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(ecosystem, severity, search, page, sortBy)
  }, [load, ecosystem, severity, search, page, sortBy])

  function handleEco(eco: string) {
    setEcosystem(eco === 'ALL' ? null : eco)
    setPage(1)
  }

  function handleSev(sev: string) {
    setSeverity(sev === 'ALL' ? null : sev)
    setPage(1)
  }

  function handleSearch(v: string) {
    setSearch(v)
    setPage(1)
  }

  function clearSearch() {
    setSearch('')
    setPage(1)
  }

  function handleSortBy(sort: 'modified' | 'cvss') {
    setSortBy(sort)
    setPage(1)
  }

  const totalPages = result ? Math.ceil(result.total / PER_PAGE) : 0

  // 重要度別カウントをヘッダーに表示
  const critCount = stats?.severities.find(s => s.severity === 'CRITICAL')?.count ?? 0
  const highCount = stats?.severities.find(s => s.severity === 'HIGH')?.count ?? 0

  return {
    ecosystem, severity, search, sortBy, page, setPage,
    result, stats, loading,
    load, handleEco, handleSev, handleSearch, clearSearch, handleSortBy,
    totalPages, critCount, highCount,
  }
}
