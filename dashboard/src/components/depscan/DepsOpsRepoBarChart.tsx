import { RepoBarChart } from '../shared/RepoBarChart'
import type { DepsOpsRepoStat } from '../../api/client'

// 要確認PRの棒の色（DEPSCAN と見分けるため、暖色から始める）
const DEPSOPS_PALETTE = [
  '#f59e0b', '#f97316', '#f43f5e', '#8b5cf6',
  '#7c3aed', '#0ea5e9', '#22d3ee', '#6366f1',
]

// リポジトリ別「要確認」PR件数の棒グラフ（上位8件。同一PRの重複日数分はAPI
// 側（GET /api/depsops/stats）で最新状態のみに集約済みのデータを受け取る）
export function DepsOpsRepoBarChart({ stats, loading }: { stats: DepsOpsRepoStat[]; loading: boolean }) {
  return (
    <RepoBarChart
      data={stats}
      loading={loading}
      title="リポジトリ別 要確認PR件数（未解決）"
      description="セキュリティ課題の件数ではありません。CI未設定のリポジトリは全PRが機械的に「要確認」になります。"
      palette={DEPSOPS_PALETTE}
    />
  )
}
