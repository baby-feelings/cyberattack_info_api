import { useCallback, useEffect, useState } from 'react'
import {
  fetchOsvList, fetchOsvStats,
  type OsvListResponse, type OsvStatsResponse,
} from '../../api/client'
import { useWatchKeywords } from '../../hooks/useWatchKeywords'
import { useKeywordCounts } from '../shared/useKeywordCounts'

const PER_PAGE = 30

// 期間の選択肢（直近 N 日）。初期は直近30日
export const OSV_PERIODS = [
  { value: 7, label: '7日' },
  { value: 30, label: '30日' },
  { value: 90, label: '90日' },
  { value: 180, label: '180日' },
]

// OsvPanel のデータ取得・フィルタ状態管理ロジックを切り出したカスタムフック。
// OsvPanel本体はUIレンダリングに専念させる（Separation of Concerns）。
// フィルタ条件・表示内容（挙動）はOsvPanelから移植前と変更していない。
export function useOsvData() {
  const [ecosystem, setEcosystem] = useState<string | null>(null)
  const [severity, setSeverity] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState<'modified' | 'cvss'>('modified')
  const [period, setPeriod] = useState(30)
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<OsvListResponse | null>(null)
  const [stats, setStats] = useState<OsvStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [statsLoading, setStatsLoading] = useState(true)
  const { keywords, add, remove } = useWatchKeywords()

  // 一覧（フィルタ・ページ）とグラフ用の統計は独立して取得する。統計はページ送り
  // では変化しないため、ページ送りのたびにグラフが読み込み中表示に戻るのを防ぐ
  const loadList = useCallback(async (
    eco: string | null, sev: string | null, q: string,
    p: number, sort: 'modified' | 'cvss', days: number,
  ) => {
    setLoading(true)
    try {
      const list = await fetchOsvList({ ecosystem: eco, severity: sev, search: q, page: p, perPage: PER_PAGE, sortBy: sort, days })
      setResult(list)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setLoading(false)
    }
  }, [])

  const loadStats = useCallback(async (days: number) => {
    setStatsLoading(true)
    try {
      const st = await fetchOsvStats(days)
      setStats(st)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setStatsLoading(false)
    }
  }, [])

  const load = useCallback((
    eco: string | null, sev: string | null, q: string,
    p: number, sort: 'modified' | 'cvss', days: number,
  ) => {
    loadList(eco, sev, q, p, sort, days)
    loadStats(days)
  }, [loadList, loadStats])

  useEffect(() => {
    loadList(ecosystem, severity, search, page, sortBy, period)
  }, [loadList, ecosystem, severity, search, page, sortBy, period])

  useEffect(() => {
    loadStats(period)
  }, [loadStats, period])

  // キーワードごとの該当件数（期間内。エコシステム・重要度の絞り込みには左右されない）
  const countFor = useCallback(
    async (keyword: string) => (await fetchOsvList({ search: keyword, days: period, perPage: 1 })).total,
    [period],
  )
  const keywordCounts = useKeywordCounts(keywords, countFor)

  function handlePeriod(next: number) {
    setPeriod(next)
    setPage(1)
  }

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
    ecosystem, severity, search, sortBy, period, page, setPage,
    result, stats, loading, statsLoading,
    load, handleEco, handleSev, handleSearch, clearSearch, handleSortBy, handlePeriod,
    totalPages, critCount, highCount,
    keywords, keywordCounts, addKeyword: add, removeKeyword: remove,
  }
}
