// 外部サイトへのリンクの組み立て。NVD・OSV・GitHub への URL を、各コンポーネントが
// 個別に文字列で組み立てていたものを、ここに集約する（DRY。ホスト名やパスの変更を1か所で済ませる）。

const NVD_BASE = 'https://nvd.nist.gov/vuln/detail'
const OSV_BASE = 'https://osv.dev/vulnerability'
const GITHUB_BASE = 'https://github.com'

/** NVD の CVE 詳細ページ。 */
export function nvdUrl(cveId: string): string {
  return `${NVD_BASE}/${cveId}`
}

/** OSV の脆弱性詳細ページ。 */
export function osvUrl(osvId: string): string {
  return `${OSV_BASE}/${osvId}`
}

/** GitHub のリポジトリのページ（`owner/name`）。 */
export function githubRepoUrl(repoFullName: string): string {
  return `${GITHUB_BASE}/${repoFullName}`
}

/** GitHub のプルリクエストのページ。 */
export function githubPullUrl(repoFullName: string, prNumber: number): string {
  return `${githubRepoUrl(repoFullName)}/pull/${prNumber}`
}
