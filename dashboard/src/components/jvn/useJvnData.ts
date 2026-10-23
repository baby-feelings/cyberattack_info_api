import { useCallback, useEffect, useState } from 'react'
import {
  fetchJvnList, fetchJvnStats,
  type JvnListResponse, type JvnStatsResponse,
} from '../../api/client'
import { useWatchKeywords } from '../../hooks/useWatchKeywords'
import { useKeywordCounts } from '../shared/useKeywordCounts'

const PER_PAGE = 30

// 期間の選択肢（直近 N 日）。初期は直近30日
export const JVN_PERIODS = [
  { value: 7, label: '7日' },
  { value: 30, label: '30日' },
  { value: 90, label: '90日' },
  { value: 180, label: '180日' },
]

// JvnPanel のデータ取得・フィルタ状態管理ロジック（OsvPanel の useOsvData と同じ構成）。
// 一覧（フィルタ・ページ）とグラフ用の統計は独立して取得する
export function useJvnData() {
  const [severity, setSeverity] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState<'modified' | 'cvss'>('modified')
  const [period, setPeriod] = useState(30)
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<JvnListResponse | null>(null)
  const [stats, setStats] = useState<JvnStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [statsLoading, setStatsLoading] = useState(true)
  const { keywords, add, remove } = useWatchKeywords()

  // 統計はページ送りでは変化しないため、ページ送りのたびにグラフが読み込み中表示に戻るのを防ぐ
  const loadList = useCallback(async (
    sev: string | null, q: string, p: number, sort: 'modified' | 'cvss', days: number,
  ) => {
    setLoading(true)
    try {
      setResult(await fetchJvnList({ severity: sev, search: q, page: p, perPage: PER_PAGE, sortBy: sort, days }))
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setLoading(false)
    }
  }, [])

  const loadStats = useCallback(async (days: number) => {
    setStatsLoading(true)
    try {
      setStats(await fetchJvnStats(days))
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setStatsLoading(false)
    }
  }, [])

  const load = useCallback((
    sev: string | null, q: string, p: number, sort: 'modified' | 'cvss', days: number,
  ) => {
    loadList(sev, q, p, sort, days)
    loadStats(days)
  }, [loadList, loadStats])

  useEffect(() => {
    loadList(severity, search, page, sortBy, period)
  }, [loadList, severity, search, page, sortBy, period])

  useEffect(() => {
    loadStats(period)
  }, [loadStats, period])

  // キーワードごとの該当件数（期間内。重要度の絞り込みには左右されない）
  const countFor = useCallback(
    async (keyword: string) => (await fetchJvnList({ search: keyword, days: period, perPage: 1 })).total,
    [period],
  )
  const keywordCounts = useKeywordCounts(keywords, countFor)

  function handleSev(sev: string) {
    setSeverity(sev === 'ALL' ? null : sev)
    setPage(1)
  }

  function handleSearch(v: string) {
    setSearch(v)
    setPage(1)
  }

  function handleSortBy(sort: 'modified' | 'cvss') {
    setSortBy(sort)
    setPage(1)
  }

  function handlePeriod(next: number) {
    setPeriod(next)
    setPage(1)
  }

  const totalPages = result ? Math.ceil(result.total / PER_PAGE) : 0

  // 対応が必要とみなす深刻度（JVN は High）の件数
  const highCount = stats?.severities.find(s => s.severity === 'High')?.count ?? 0

  return {
    severity, search, sortBy, period, page, setPage,
    result, stats, loading, statsLoading,
    load, handleSev, handleSearch, handleSortBy, handlePeriod,
    totalPages, highCount,
    keywords, keywordCounts, addKeyword: add, removeKeyword: remove,
  }
}
