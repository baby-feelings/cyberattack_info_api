import { useState } from 'react'
import type { OperatingStatus } from '../../api/client'

// DEPSCAN・CODESCAN の一覧で共通の、絞り込み条件（重要度・運用状態・アプリ・例外の表示）とページの状態。
// 条件を変えたら、ページを1に戻す。画面ごとの違いは、options で受け取る
export function useFindingFilters({ resetRepoOnOperating = false }: {
  // 運用状態を切り替えたとき、選んでいたアプリを戻すか（一覧がサーバー側の絞り込みで、選んでいたアプリが消えることがある画面）
  resetRepoOnOperating?: boolean
} = {}) {
  const [severity, setSeverity] = useState<string | null>(null)
  // 例外（受容・影響なし・誤検知）にした検知を含めるか。初期は含めない（対応が必要なものだけを見せる）
  const [showExcepted, setShowExcepted] = useState(false)
  // 初期表示は運用中のみ（運用停止中のアプリの脆弱性に埋もれず、運用中のものを見やすくするため）
  const [operating, setOperating] = useState<OperatingStatus>('active')
  // 左のアプリ一覧で選んでいるリポジトリ（null = すべてのアプリ）
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null)
  const [page, setPage] = useState(1)

  const resetPage = () => setPage(1)

  return {
    severity, showExcepted, operating, selectedRepo, page, setPage, resetPage,
    handleSev: (sev: string) => { setSeverity(sev === 'ALL' ? null : sev); resetPage() },
    handleOperating: (op: OperatingStatus) => {
      setOperating(op)
      if (resetRepoOnOperating) setSelectedRepo(null)
      resetPage()
    },
    handleRepo: (repo: string | null) => { setSelectedRepo(repo); resetPage() },
    toggleShowExcepted: () => { setShowExcepted(v => !v); resetPage() },
  }
}
