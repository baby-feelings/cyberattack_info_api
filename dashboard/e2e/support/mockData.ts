// E2E用のモックデータ生成。フィルター・ページ送りに実際に反応するよう、
// 件数・属性は添字から決定論的に生成する（テストの再現性を保つ）。

export const PER_PAGE_KEV = 30

const pad = (n: number, width = 4) => String(n).padStart(width, '0')
const isoDay = (offsetDays: number) =>
  new Date(Date.UTC(2026, 8, 20) - offsetDays * 86_400_000).toISOString()

// ── KEV ───────────────────────────────────────────────────────────

const KEV_VENDORS = ['Microsoft', 'Apple', 'Cisco', 'Google']
const KEV_PRODUCTS = ['Windows', 'iOS', 'IOS XE', 'Chromium']

export const KEV_TOTAL = 65

export const kevItems = Array.from({ length: KEV_TOTAL }, (_, i) => ({
  cve_id: `CVE-2026-${pad(i + 1)}`,
  vendor_project: KEV_VENDORS[i % 4],
  product: KEV_PRODUCTS[i % 4],
  vulnerability_name: `${KEV_VENDORS[i % 4]} ${KEV_PRODUCTS[i % 4]} 脆弱性 #${i + 1}`,
  description: `説明文 ${i + 1}: ${KEV_VENDORS[i % 4]} 製品にリモートコード実行の脆弱性が存在する。`,
  required_action: i % 5 === 4 ? null : `ベンダーの指示に従い修正パッチを適用する (#${i + 1})`,
  date_added: isoDay(i).slice(0, 10),
  // 1件目は高EPSS、2件目はEPSS未取得（null）にして両方の表示分岐を通す
  epss_score: i === 1 ? null : i === 0 ? 0.9732 : 0.0123,
  epss_percentile: i === 1 ? null : 0.98,
  epss_updated_at: i === 1 ? null : '2026-09-19T00:00:00Z',
}))

export function kevStats() {
  const counts = new Map<string, number>()
  for (const v of kevItems) counts.set(v.vendor_project, (counts.get(v.vendor_project) ?? 0) + 1)
  return {
    total_vulnerabilities: kevItems.length,
    top_vendors: [...counts].map(([vendor_project, count]) => ({ vendor_project, count }))
      .sort((a, b) => b.count - a.count),
    monthly_trend: [
      { year_month: '2026-07', count: 12 },
      { year_month: '2026-08', count: 20 },
      { year_month: '2026-09', count: 33 },
    ],
  }
}

// ── OSV ───────────────────────────────────────────────────────────

export const OSV_ECOSYSTEMS = ['PyPI', 'npm', 'Go', 'Maven']
const OSV_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
export const OSV_TOTAL = 65

export const osvItems = Array.from({ length: OSV_TOTAL }, (_, i) => ({
  osv_id: `GHSA-e2e${pad(i + 1)}`,
  ecosystem: OSV_ECOSYSTEMS[i % 4],
  package_name: `pkg-${OSV_ECOSYSTEMS[i % 4].toLowerCase()}-${i + 1}`,
  aliases: [`CVE-2026-9${pad(i + 1)}`, `GHSA-alias-${i + 1}`],
  summary: `OSV概要 ${i + 1}: ${OSV_ECOSYSTEMS[i % 4]} パッケージの脆弱性`,
  details: `OSV詳細 ${i + 1}: 入力検証の不備により任意コード実行が可能。`,
  // 5件に1件は深刻度・CVSSが未設定（N/A表示の分岐）
  severity: i % 5 === 4 ? null : OSV_SEVERITIES[i % 4],
  cvss_score: i % 5 === 4 ? null : 9.8 - (i % 4) * 2,
  affected_versions: ['1.0.0', '1.1.0'],
  fixed_versions: i % 3 === 0 ? [] : [`2.0.${i}`],
  references: [`https://example.test/advisory/${i + 1}`],
  published: isoDay(i + 10),
  modified: isoDay(i),
}))

export function osvStats() {
  const eco = new Map<string, number>()
  const sev = new Map<string, number>()
  for (const v of osvItems) {
    eco.set(v.ecosystem, (eco.get(v.ecosystem) ?? 0) + 1)
    const s = v.severity ?? 'N/A'
    sev.set(s, (sev.get(s) ?? 0) + 1)
  }
  return {
    total: osvItems.length,
    ecosystems: [...eco].map(([ecosystem, count]) => ({ ecosystem, count })),
    severities: [...sev].map(([severity, count]) => ({ severity, count })),
    monthly_trend: [
      { year_month: '2026-08', count: 25 },
      { year_month: '2026-09', count: 40 },
    ],
  }
}

// ── JVN ───────────────────────────────────────────────────────────

const JVN_SEVERITIES = ['High', 'Medium', 'Low']
export const JVN_TOTAL = 40

export const jvnItems = Array.from({ length: JVN_TOTAL }, (_, i) => ({
  jvndb_id: `JVNDB-2026-${pad(i + 1, 6)}`,
  title: `JVNタイトル ${i + 1}: 国内製品の脆弱性`,
  overview: `JVN概要 ${i + 1}: クロスサイトスクリプティングの脆弱性。`,
  cve_ids: [`CVE-2026-8${pad(i + 1)}`],
  severity: JVN_SEVERITIES[i % 3],
  cvss_score: 8.1 - (i % 3) * 2,
  cvss_vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
  // 1件目は影響製品が複数（「+N 製品」表示の分岐）、2件目は影響製品なし（「—」表示）
  affected_products: i === 1 ? [] : [
    { vendor: 'ACME', product: `Widget ${i + 1}`, cpe: 'cpe:/a:acme:widget' },
    ...(i === 0 ? [{ vendor: 'ACME', product: 'Gadget', cpe: 'cpe:/a:acme:gadget' }] : []),
  ],
  references: [],
  jvn_url: `https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-${pad(i + 1, 6)}.html`,
  date_published: isoDay(i + 5),
  date_last_modified: isoDay(i),
}))

export function jvnStats() {
  const sev = new Map<string, number>()
  for (const v of jvnItems) sev.set(v.severity, (sev.get(v.severity) ?? 0) + 1)
  return {
    total: jvnItems.length,
    severities: [...sev].map(([severity, count]) => ({ severity, count })),
    monthly_trend: [
      { year_month: '2026-08', count: 15 },
      { year_month: '2026-09', count: 25 },
    ],
  }
}

// ── DEPSCAN ───────────────────────────────────────────────────────

interface FindingSeed {
  repo: string
  pkg: string
  version: string
  osv: string
  severity: string | null
  cvss: number | null
  resolved?: boolean
  reasons?: string[]
  fixed?: string[]
  visibility?: 'public' | 'private' | null
  reachability?: 'reachable' | 'unreachable' | 'unknown' | null
}

const FINDING_SEEDS: FindingSeed[] = [
  // 同一パッケージ×バージョンに2件（グループ集約・展開の確認用）
  { repo: 'baby-feelings/app-one', pkg: 'lodash', version: '4.17.15', osv: 'GHSA-lodash-1', severity: 'CRITICAL', cvss: 9.8,
    reasons: ['kev_listed', 'reachable'], fixed: ['4.17.21'], visibility: 'public', reachability: 'reachable' },
  { repo: 'baby-feelings/app-one', pkg: 'lodash', version: '4.17.15', osv: 'GHSA-lodash-2', severity: 'HIGH', cvss: 7.4,
    reasons: ['public_repo'], fixed: ['4.17.19'], visibility: 'public', reachability: 'reachable' },
  { repo: 'baby-feelings/app-two', pkg: 'requests', version: '2.19.0', osv: 'GHSA-requests-1', severity: 'MEDIUM', cvss: 5.3,
    fixed: [], visibility: 'private', reachability: 'unreachable' },
  { repo: 'other-owner/tool', pkg: 'express', version: '4.16.0', osv: 'GHSA-express-1', severity: 'LOW', cvss: 3.1,
    fixed: ['4.17.3'], visibility: null, reachability: null },
  // 解決済み（デフォルトでは非表示、「解決済みを含む」で表示）
  { repo: 'baby-feelings/app-one', pkg: 'minimist', version: '1.2.0', osv: 'GHSA-minimist-1', severity: 'HIGH', cvss: 7.5,
    resolved: true, fixed: ['1.2.6'], visibility: 'public', reachability: 'unknown' },
]

export const depscanFindings = FINDING_SEEDS.map((s) => ({
  repo_full_name: s.repo,
  ecosystem: s.pkg === 'requests' ? 'PyPI' : 'npm',
  package_name: s.pkg,
  installed_version: s.version,
  osv_id: s.osv,
  severity: s.severity,
  cvss_score: s.cvss,
  summary: `${s.pkg} の脆弱性 (${s.osv})`,
  fixed_versions: s.fixed ?? [],
  manifest_path: 'package-lock.json',
  reachability: s.reachability ?? null,
  repo_visibility: s.visibility ?? null,
  priority_reasons: s.reasons ?? [],
  detected_at: '2026-09-15T00:00:00Z',
  resolved_at: s.resolved ? '2026-09-18T00:00:00Z' : null,
}))

export function depscanStats() {
  const open = depscanFindings.filter((f) => !f.resolved_at)
  const repos = new Map<string, number>()
  const sev = new Map<string, number>()
  for (const f of open) {
    repos.set(f.repo_full_name, (repos.get(f.repo_full_name) ?? 0) + 1)
    const s = f.severity ?? 'N/A'
    sev.set(s, (sev.get(s) ?? 0) + 1)
  }
  return {
    total: open.length,
    repos: [...repos].map(([repo_full_name, count]) => ({ repo_full_name, count })),
    severities: [...sev].map(([severity, count]) => ({ severity, count })),
  }
}

// ── DEPSOPS ───────────────────────────────────────────────────────

// 解決済みPRは履歴ごと削除されるため、判定は自動マージと要確認の2種のみ
const DEPSOPS_ACTIONS = ['merged', 'flagged'] as const
export const DEPSOPS_TOTAL = 45

export const depsopsItems = Array.from({ length: DEPSOPS_TOTAL }, (_, i) => ({
  repo_full_name: i % 2 === 0 ? 'baby-feelings/app-one' : 'baby-feelings/app-two',
  pr_number: 100 + i,
  title: `Bump dep-${i + 1} from 1.0.${i} to 1.0.${i + 1}`,
  action: DEPSOPS_ACTIONS[i % 2],
  reason: DEPSOPS_ACTIONS[i % 2] === 'flagged' ? `メジャーアップデートのため要確認 (#${100 + i})` : null,
  // 3値（true/false/null）すべてを通す
  is_security_update: i % 3 === 0 ? true : i % 3 === 1 ? false : null,
  compatibility_badge_url: i % 2 === 0
    ? 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="80" height="20"></svg>'
    : null,
  processed_at: isoDay(i),
}))

// ── CODESCAN ──────────────────────────────────────────────────────

const CODESCAN_SEVERITIES = ['ERROR', 'WARNING', 'INFO']
export const CODESCAN_TOTAL = 35

export const codescanItems = Array.from({ length: CODESCAN_TOTAL }, (_, i) => {
  const gitleaks = i % 4 === 0
  return {
    repo_full_name: i % 2 === 0 ? 'baby-feelings/app-one' : 'baby-feelings/app-two',
    file_path: `src/module${i + 1}.ts`,
    line_start: 10 + i,
    line_end: 12 + i,
    rule_id: gitleaks ? 'gitleaks:generic-api-key' : `javascript.lang.security.rule-${i + 1}`,
    message: `CODESCAN検知メッセージ ${i + 1}`,
    severity: CODESCAN_SEVERITIES[i % 3],
    cwe_ids: i % 2 === 0 ? ['CWE-798'] : [],
    owasp_categories: i % 2 === 0 ? ['A07:2021 - Identification and Authentication Failures'] : [],
    code_snippet: i % 3 === 2 ? '' : `const secret = "***REDACTED-${i + 1}"`,
    // 先頭は7.0以上（赤バッジ）、2番目は未算出（null）、それ以外は低スコア
    cvss_score: i === 0 ? 8.6 : i === 1 ? null : 4.3,
    cvss_vector: i === 1 ? null : 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    tool: gitleaks ? 'gitleaks' : 'semgrep',
    detected_at: isoDay(i),
    // 末尾3件は解決済み
    resolved_at: i >= CODESCAN_TOTAL - 3 ? isoDay(0) : null,
  }
})

export function codescanStats() {
  const open = codescanItems.filter((f) => !f.resolved_at)
  const repos = new Map<string, number>()
  const sev = new Map<string, number>()
  for (const f of open) {
    repos.set(f.repo_full_name, (repos.get(f.repo_full_name) ?? 0) + 1)
    sev.set(f.severity, (sev.get(f.severity) ?? 0) + 1)
  }
  return {
    total: open.length,
    repos: [...repos].map(([repo_full_name, count]) => ({ repo_full_name, count })),
    severities: [...sev].map(([severity, count]) => ({ severity, count })),
  }
}
