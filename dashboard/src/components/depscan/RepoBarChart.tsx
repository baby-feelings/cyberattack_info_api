import { RepoBarChart as SharedRepoBarChart } from '../shared/RepoBarChart'
import type { DepscanStatsResponse } from '../../api/client'

// DEPSCAN のリポジトリ別件数（未解決）
export function RepoBarChart({ stats, loading }: { stats: DepscanStatsResponse | null; loading: boolean }) {
  return <SharedRepoBarChart data={stats?.repos ?? []} loading={loading} title="リポジトリ別件数（未解決）" />
}
