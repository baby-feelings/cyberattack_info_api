import type { DependabotPrLogOut } from '../../api/client'

export interface RepoOpsStat {
  repo_full_name: string
  count: number
}

// DEPSOPS は実行のたびに判定結果を1行追加する設計のため、同じPRが複数日
// 「要確認」のままだと日数分の行がたまる。リポジトリ別に「今どれだけ
// 未解決PRが残っているか」を出すには、PR単位で最新の判定だけを見て、
// その最新状態が flagged のものだけを数える必要がある。
export function computeUnresolvedRepoStats(entries: DependabotPrLogOut[]): RepoOpsStat[] {
  const latestByPr = new Map<string, DependabotPrLogOut>()
  for (const entry of entries) {
    const key = `${entry.repo_full_name}#${entry.pr_number}`
    const existing = latestByPr.get(key)
    if (!existing || entry.processed_at > existing.processed_at) {
      latestByPr.set(key, entry)
    }
  }

  const counts = new Map<string, number>()
  for (const entry of latestByPr.values()) {
    if (entry.action !== 'flagged') continue
    counts.set(entry.repo_full_name, (counts.get(entry.repo_full_name) ?? 0) + 1)
  }

  return Array.from(counts.entries())
    .map(([repo_full_name, count]) => ({ repo_full_name, count }))
    .sort((a, b) => b.count - a.count)
}
