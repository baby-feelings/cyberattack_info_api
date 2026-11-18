import { useEffect, useState, type FormEvent } from 'react'
import {
  fetchRepoDependencies, fetchRepoDependencyRepos,
  type OperatingStatus, type RepoDependencyOut, type RepoDependencyRepoStat,
} from '../../api/client'
import { INITIAL_FILTERS, PER_PAGE, type Filters } from './dependenciesConfig'

interface ListResult {
  // この結果を取得したときの条件。現在の条件と違えば「取得中」とみなす
  filters: Filters
  items: RepoDependencyOut[]
  total: number
  failed: boolean
}

// 依存パッケージの取得と、絞り込み・検索・ページの状態（画面は、これを読んで描くだけ）
export function useDependencies(authToken?: string) {
  const [filters, setFilters] = useState<Filters>(INITIAL_FILTERS)
  // 入力欄の文字（「検索」またはEnterで filters に確定する）
  const [packageText, setPackageText] = useState('')
  const [versionText, setVersionText] = useState('')
  const [list, setList] = useState<ListResult | null>(null)
  const [repoList, setRepoList] = useState<{ operating: OperatingStatus; repos: RepoDependencyRepoStat[] } | null>(null)

  // 依存の一覧。条件が変わるたびに取り直す。状態の更新は取得の完了時だけ行う
  // （効果の中で同期的に更新しない。条件の変更で古い取得が遅れて届いても、結果を捨てる）
  useEffect(() => {
    let cancelled = false
    fetchRepoDependencies({
      page: filters.page, perPage: PER_PAGE, packageName: filters.packageName,
      version: filters.version, ecosystem: filters.ecosystem, repo: filters.repo,
      vulnerableOnly: filters.vulnerableOnly, operating: filters.operating, authToken,
    })
      .then(res => {
        if (!cancelled) setList({ filters, items: res.data, total: res.total, failed: false })
      })
      .catch(() => {
        if (!cancelled) setList({ filters, items: [], total: 0, failed: true })
      })
    return () => { cancelled = true }
  }, [filters, authToken])

  // 左のアプリ一覧。運用状態を切り替えたときだけ取り直す
  useEffect(() => {
    let cancelled = false
    fetchRepoDependencyRepos(authToken, filters.operating)
      .then(res => {
        if (!cancelled) setRepoList({ operating: filters.operating, repos: res.repos })
      })
      .catch(() => {
        if (!cancelled) setRepoList({ operating: filters.operating, repos: [] })
      })
    return () => { cancelled = true }
  }, [authToken, filters.operating])

  function update(patch: Partial<Filters>) {
    setFilters(f => ({ ...f, ...patch, page: 1 }))
  }

  function handleOperating(operating: OperatingStatus) {
    // 切り替え先に無いアプリを選んだままにしないよう、アプリの選択は外す
    update({ operating, repo: null })
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    update({ packageName: packageText, version: versionText })
  }

  function changePage(updater: (page: number) => number) {
    setFilters(f => ({ ...f, page: updater(f.page) }))
  }

  return {
    filters, update, handleOperating, handleSubmit, changePage,
    packageText, setPackageText, versionText, setVersionText,
    loading: list === null || list.filters !== filters,
    failed: list?.failed ?? false,
    items: list?.items ?? ([] as RepoDependencyOut[]),
    total: list?.total ?? 0,
    totalPages: list ? Math.ceil(list.total / PER_PAGE) : 0,
    repos: repoList?.operating === filters.operating ? repoList.repos : [],
  }
}
