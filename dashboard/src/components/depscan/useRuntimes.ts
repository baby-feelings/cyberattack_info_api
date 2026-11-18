import { useEffect, useState } from 'react'
import {
  fetchRuntimes, fetchRuntimeRepos, fetchRuntimeReleases,
  type OperatingStatus, type RepoRuntimeOut, type RepoRuntimeRepoStat, type RuntimeReleaseOut,
} from '../../api/client'
import { INITIAL_FILTERS, type Filters } from './runtimesConfig'

interface ListResult {
  // この結果を取得したときの条件。現在の条件と違えば「取得中」とみなす
  filters: Filters
  items: RepoRuntimeOut[]
  failed: boolean
}

// 言語・実行環境の取得と、絞り込みの状態（画面は、これを読んで描くだけ）
export function useRuntimes(authToken?: string) {
  const [filters, setFilters] = useState<Filters>(INITIAL_FILTERS)
  const [list, setList] = useState<ListResult | null>(null)
  const [repoList, setRepoList] = useState<{ operating: OperatingStatus; repos: RepoRuntimeRepoStat[] } | null>(null)
  const [releases, setReleases] = useState<RuntimeReleaseOut[]>([])

  // 一覧。条件が変わるたびに取り直す。状態の更新は取得の完了時だけ行う
  // （効果の中で同期的に更新しない。条件の変更で古い取得が遅れて届いても、結果を捨てる）
  useEffect(() => {
    let cancelled = false
    fetchRuntimes({
      repo: filters.repo, runtime: filters.runtime, needsAction: filters.needsActionOnly,
      operating: filters.operating, authToken,
    })
      .then(res => {
        if (!cancelled) setList({ filters, items: res.data, failed: false })
      })
      .catch(() => {
        if (!cancelled) setList({ filters, items: [], failed: true })
      })
    return () => { cancelled = true }
  }, [filters, authToken])

  // 左のアプリ一覧。運用状態を切り替えたときだけ取り直す
  useEffect(() => {
    let cancelled = false
    fetchRuntimeRepos(authToken, filters.operating)
      .then(res => {
        if (!cancelled) setRepoList({ operating: filters.operating, repos: res.repos })
      })
      .catch(() => {
        if (!cancelled) setRepoList({ operating: filters.operating, repos: [] })
      })
    return () => { cancelled = true }
  }, [authToken, filters.operating])

  // 推奨の版の表示。開いたときに1回だけ取得する（失敗しても、一覧の表示は妨げない）
  useEffect(() => {
    let cancelled = false
    fetchRuntimeReleases(authToken)
      .then(res => { if (!cancelled) setReleases(res.data) })
      .catch(() => { if (!cancelled) setReleases([]) })
    return () => { cancelled = true }
  }, [authToken])

  function update(patch: Partial<Filters>) {
    setFilters(f => ({ ...f, ...patch }))
  }

  function handleOperating(operating: OperatingStatus) {
    // 切り替え先に無いアプリを選んだままにしないよう、アプリの選択は外す
    update({ operating, repo: null })
  }

  const loading = list === null || list.filters !== filters
  const repos: RepoRuntimeRepoStat[] = repoList?.operating === filters.operating ? repoList.repos : []

  return {
    filters, update, handleOperating, loading,
    failed: list?.failed ?? false,
    items: list?.items ?? [],
    repos, releases: releases as RuntimeReleaseOut[],
  }
}
