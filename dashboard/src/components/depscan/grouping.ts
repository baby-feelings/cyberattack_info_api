import type { DependencyFindingOut } from '../../api/client'

// 深刻度バッジのスタイル（OSV と同じ CRITICAL/HIGH/MEDIUM/LOW 表記）
export const SEVERITY_CLS: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#3b82f6',
  'N/A':    '#475569',
}

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

export function severityRank(severity: string | null): number {
  return SEVERITY_ORDER[severity ?? ''] ?? 4
}

// リポジトリ full_name（"owner/repo"）からオーナー名部分を取り出す
export function ownerOf(repoFullName: string): string {
  return repoFullName.split('/')[0] ?? repoFullName
}

// サーバーは「パッケージ×CVE」単位で1件返すため、同一パッケージ・同一バージョンの
// 複数CVEを1グループに集約する（Slack通知・GitHub Issue自動起票と同じ考え方）。
export interface FindingGroup {
  repo_full_name: string
  package_name: string
  installed_version: string
  findings: DependencyFindingOut[]
}

export function groupFindings(data: DependencyFindingOut[]): FindingGroup[] {
  const map = new Map<string, FindingGroup>()
  for (const f of data) {
    const key = `${f.repo_full_name}|${f.package_name}|${f.installed_version}`
    let g = map.get(key)
    if (!g) {
      g = {
        repo_full_name: f.repo_full_name,
        package_name: f.package_name,
        installed_version: f.installed_version,
        findings: [],
      }
      map.set(key, g)
    }
    g.findings.push(f)
  }
  return Array.from(map.values())
}

export function groupBestSeverityRank(g: FindingGroup): number {
  return Math.min(...g.findings.map(f => severityRank(f.severity)))
}

export function groupLatestDetectedAt(g: FindingGroup): string {
  return g.findings.reduce((max, f) => (f.detected_at > max ? f.detected_at : max), g.findings[0].detected_at)
}

export function groupIsResolved(g: FindingGroup): boolean {
  return g.findings.every(f => f.resolved_at)
}

export function groupFixedVersions(g: FindingGroup): string[] {
  const set = new Set<string>()
  for (const f of g.findings) {
    for (const v of f.fixed_versions) set.add(v)
  }
  return Array.from(set).sort()
}

export function groupSeverityCounts(g: FindingGroup): [string, number][] {
  const counts = new Map<string, number>()
  for (const f of g.findings) {
    const sev = f.severity ?? 'N/A'
    counts.set(sev, (counts.get(sev) ?? 0) + 1)
  }
  return Array.from(counts.entries()).sort(
    (a, b) => severityRank(a[0] === 'N/A' ? null : a[0]) - severityRank(b[0] === 'N/A' ? null : b[0]),
  )
}
