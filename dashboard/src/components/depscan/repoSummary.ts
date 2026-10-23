import type { DependencyFindingOut } from '../../api/client'

// 左のアプリ一覧に出す、リポジトリごとの件数
export interface RepoSummary {
  repo: string
  // 未解決の CRITICAL / HIGH の件数（「対応が必要」の件数）
  crit: number
  high: number
  // 表示中の脆弱性の総件数
  total: number
}

// 取得済みの検知結果を、リポジトリ単位に集計する。
// 「対応が必要」（未解決の CRITICAL・HIGH）が多いアプリ、次に総件数が多いアプリの順に並べる
export function summarizeRepos(findings: DependencyFindingOut[]): RepoSummary[] {
  const map = new Map<string, RepoSummary>()
  for (const f of findings) {
    let s = map.get(f.repo_full_name)
    if (!s) {
      s = { repo: f.repo_full_name, crit: 0, high: 0, total: 0 }
      map.set(f.repo_full_name, s)
    }
    s.total += 1
    if (!f.resolved_at) {
      if (f.severity === 'CRITICAL') s.crit += 1
      else if (f.severity === 'HIGH') s.high += 1
    }
  }
  return Array.from(map.values()).sort((a, b) => {
    const urgent = (b.crit + b.high) - (a.crit + a.high)
    if (urgent !== 0) return urgent
    if (b.total !== a.total) return b.total - a.total
    return a.repo.localeCompare(b.repo)
  })
}
