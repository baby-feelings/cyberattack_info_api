import { useCallback, useEffect, useState } from 'react'
import {
  fetchDepsOpsList, fetchDepsOpsStats, type DependabotPrLogOut, type DepsOpsRepoStat,
  type OperatingStatus,
} from '../../api/client'
import { PER_PAGE, type ActionFilter } from './dependabotOpsConfig'

// Dependabot 運用状況の取得と、絞り込み・ページの状態（画面は、これを読んで描くだけ）
export function useDependabotOps() {
  const [action, setAction] = useState<ActionFilter>('ALL')
  // 初期表示は運用中のみ（運用停止中のアプリのPRに埋もれず、運用中のものを見やすくするため）
  const [operating, setOperating] = useState<OperatingStatus>('active')
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [items, setItems] = useState<DependabotPrLogOut[]>([])
  const [loading, setLoading] = useState(false)
  const [repoStats, setRepoStats] = useState<DepsOpsRepoStat[]>([])
  const [statsLoading, setStatsLoading] = useState(false)

  const loadTable = useCallback(async (act: ActionFilter, p: number, op: OperatingStatus) => {
    setLoading(true)
    try {
      const res = await fetchDepsOpsList({
        page: p, perPage: PER_PAGE, action: act === 'ALL' ? null : act, operating: op,
      })
      setItems(res.data)
      setTotal(res.total)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setLoading(false)
    }
  }, [])

  const loadStats = useCallback(async (op: OperatingStatus) => {
    setStatsLoading(true)
    try {
      const res = await fetchDepsOpsStats(op)
      setRepoStats(res.repos)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setStatsLoading(false)
    }
  }, [])

  // 表示されたとき（と、条件が変わったとき）に取得する
  useEffect(() => {
    loadTable(action, page, operating)
  }, [loadTable, action, page, operating])

  useEffect(() => {
    loadStats(operating)
  }, [loadStats, operating])

  function handleOperating(op: OperatingStatus) {
    setOperating(op)
    setPage(1)
  }

  function handleAction(act: ActionFilter) {
    setAction(act)
    setPage(1)
  }

  return {
    action, operating, page, setPage, total, items, loading, repoStats, statsLoading,
    totalPages: Math.ceil(total / PER_PAGE),
    handleOperating, handleAction,
  }
}
