import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  fetchVulnerabilities, fetchStats, fetchRecent,
  type VulnerabilityListResponse, type StatsResponse, type VulnerabilityOut,
} from '../../api/client'
import { useWatchKeywords } from '../../hooks/useWatchKeywords'
import { useKeywordCounts } from '../shared/useKeywordCounts'

const PER_PAGE = 30
// 悪用されやすいとみなす EPSS の下限（10%）。帯の「悪用されやすい」件数の基準
export const EPSS_HIGH = 0.1

// 期間の選択肢（null = すべて）。初期は直近30日
export const KEV_PERIODS = [
  { value: 7, label: '7日' },
  { value: 30, label: '30日' },
  { value: 90, label: '90日' },
  { value: null, label: 'すべて' },
]

// サーバーの search（ベンダー名 OR 製品名の部分一致・大文字小文字を区別しない）と同じ判定
function matchesKeyword(item: VulnerabilityOut, keyword: string): boolean {
  const k = keyword.trim().toLowerCase()
  if (k === '') return true
  return item.vendor_project.toLowerCase().includes(k) || item.product.toLowerCase().includes(k)
}

// KevPanel のデータ取得・フィルタ状態管理ロジック（OsvPanel の useOsvData と同じ構成）。
// 期間を絞るとき（7/30/90日）は「直近の追加」API で期間内の全件を取得し、検索と
// ページ分割は画面側で行う（期間内は数十件程度）。「すべて」は従来どおりサーバー側のページ分割
export function useKevData() {
  const [search, setSearch] = useState('')
  const [period, setPeriod] = useState<number | null>(30)
  const [page, setPage] = useState(1)
  const [serverResult, setServerResult] = useState<VulnerabilityListResponse | null>(null)
  const [recent, setRecent] = useState<VulnerabilityOut[] | null>(null)
  // 「すべて」のときの、EPSS が高い脆弱性の総数（期間を絞るときは recent から数える）
  const [epssHighAll, setEpssHighAll] = useState<number | null>(null)
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [statsLoading, setStatsLoading] = useState(true)
  const { keywords, add, remove } = useWatchKeywords()
  // 直近N日の一覧を取得済みの期間（同じ期間のまま検索・ページを変えても取り直さないため）
  const recentLoadedFor = useRef<number | null>(null)
  // 「すべて」の EPSS が高い件数を取得済みか（ページ送り・検索のたびには取り直さない）
  const epssHighLoaded = useRef(false)

  // 一覧（検索・ページ・期間）とグラフ用の統計は独立して取得する。統計はページ送り
  // では変化しないため、ページ送りのたびにグラフが読み込み中表示に戻るのを防ぐ
  const loadList = useCallback(async (q: string, p: number, per: number | null, force = false) => {
    // 期間を絞るときは、同じ期間の一覧を取得済みなら取り直さない（検索・ページは画面側で絞る）
    if (per !== null && !force && recentLoadedFor.current === per) return
    // 取得の開始時点で記録する（開発時の二重実行などで、同じ取得を重複して走らせないため）。失敗したら戻す
    if (per !== null) recentLoadedFor.current = per
    setLoading(true)
    try {
      if (per === null) {
        setServerResult(await fetchVulnerabilities({ search: q, page: p, perPage: PER_PAGE }))
        if (force || !epssHighLoaded.current) {
          epssHighLoaded.current = true
          try {
            setEpssHighAll((await fetchVulnerabilities({ minEpss: EPSS_HIGH, perPage: 1 })).total)
          } catch {
            epssHighLoaded.current = false
            throw new Error('EPSS の件数を取得できません')
          }
        }
      } else {
        setRecent(await fetchRecent(per))
      }
    } catch {
      if (per !== null) recentLoadedFor.current = null
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setLoading(false)
    }
  }, [])

  const loadStats = useCallback(async () => {
    setStatsLoading(true)
    try {
      setStats(await fetchStats())
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setStatsLoading(false)
    }
  }, [])

  // 手動の再読み込み。取得済みの期間でも取り直す
  const load = useCallback((q: string, p: number, per: number | null) => {
    loadList(q, p, per, true)
    loadStats()
  }, [loadList, loadStats])

  useEffect(() => {
    loadList(search, page, period)
  }, [loadList, period, search, page])

  useEffect(() => {
    loadStats()
  }, [loadStats])

  function handleSearch(v: string) {
    setSearch(v)
    setPage(1)
  }

  function handlePeriod(next: number | null) {
    setPeriod(next)
    setPage(1)
  }

  // 一覧に出す行・総数。期間を絞るときは取得済みの期間内の全件を、検索語で絞ってページ分割する
  const filtered = useMemo(
    () => (period !== null && recent ? recent.filter(i => matchesKeyword(i, search)) : []),
    [period, recent, search],
  )
  const rows: VulnerabilityOut[] = period !== null
    ? filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE)
    : (serverResult?.data ?? [])
  const total = period !== null
    ? (recent === null ? null : filtered.length)
    : (serverResult?.total ?? null)
  const totalPages = total === null ? 0 : Math.ceil(total / PER_PAGE)

  // 帯の数字（期間内の追加件数と、そのうち EPSS が高い件数）。検索語には左右されない
  const periodTotal = period !== null ? (recent?.length ?? null) : (stats?.total_vulnerabilities ?? null)
  const epssHigh = period !== null
    ? (recent === null ? null : recent.filter(i => (i.epss_score ?? 0) >= EPSS_HIGH).length)
    : epssHighAll

  // キーワードごとの該当件数。期間を絞るときは取得済みの一覧から数え、「すべて」は検索 API で数える
  const countFor = useCallback(async (keyword: string): Promise<number> => {
    if (period === null) return (await fetchVulnerabilities({ search: keyword, perPage: 1 })).total
    if (recent === null) throw new Error('期間内の一覧を取得中')
    return recent.filter(i => matchesKeyword(i, keyword)).length
  }, [period, recent])
  const keywordCounts = useKeywordCounts(keywords, countFor)

  return {
    search, period, page, setPage,
    rows, total, totalPages, stats, loading, statsLoading,
    periodTotal, epssHigh,
    keywords, keywordCounts, addKeyword: add, removeKeyword: remove,
    load, handleSearch, handlePeriod,
  }
}
