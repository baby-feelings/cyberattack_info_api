import { RepoBarChart as SharedRepoBarChart } from '../shared/RepoBarChart'
import type { CodescanStatsResponse } from '../../api/codescan'

// CODESCAN のリポジトリ別件数。対応が必要な件数に、例外にした件数を積み上げて表示する
// （例外だけのリポジトリも出して、下の一覧と食い違わないようにする）
export function RepoBarChart({ stats, loading }: { stats: CodescanStatsResponse | null; loading: boolean }) {
  return (
    <SharedRepoBarChart
      data={stats?.repos ?? []}
      loading={loading}
      title="リポジトリ別件数（未解決）"
      countName="対応が必要"
      exceptedName="例外（受容・影響なし など）"
    />
  )
}
