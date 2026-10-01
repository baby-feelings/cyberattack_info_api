import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import type { FullResult, Reporter, TestCase, TestResult } from '@playwright/test/reporter'
import { SCENARIOS } from '../support/scenarios'

// シナリオ網羅率レポーター。
// 「合格したシナリオ数 ÷ カタログ総数」を計算してHTMLに出力し、合格ライン
// （既定90%）を下回る、またはカタログ外のIDがテストに使われていたら失敗にする。

interface Options {
  threshold?: number
  outputFile?: string
}

type Status = 'passed' | 'failed' | 'skipped' | 'missing'

const escapeHtml = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

export default class ScenarioCoverageReporter implements Reporter {
  private readonly threshold: number
  private readonly outputFile: string
  // シナリオID → (テストID → 最終試行の結果)。リトライ時は後の試行で上書きされる
  private readonly results = new Map<string, Map<string, TestResult['status']>>()
  private readonly unknownIds = new Set<string>()
  private readonly catalogIds = new Set<string>(SCENARIOS.map((s) => s.id))

  constructor(options: Options = {}) {
    this.threshold = options.threshold ?? 0.9
    this.outputFile = options.outputFile ?? 'playwright-report/scenario-coverage.html'
  }

  printsToStdio() {
    return false
  }

  onTestEnd(test: TestCase, result: TestResult) {
    for (const a of test.annotations) {
      if (a.type !== 'scenario' || !a.description) continue
      if (!this.catalogIds.has(a.description)) this.unknownIds.add(a.description)
      const byTest = this.results.get(a.description) ?? new Map<string, TestResult['status']>()
      byTest.set(test.id, result.status)
      this.results.set(a.description, byTest)
    }
  }

  private statusOf(id: string): Status {
    const byTest = this.results.get(id)
    if (!byTest) return 'missing'
    const list = [...byTest.values()]
    if (list.some((s) => s === 'failed' || s === 'timedOut' || s === 'interrupted')) return 'failed'
    if (list.every((s) => s === 'skipped')) return 'skipped'
    return 'passed'
  }

  async onEnd(result: FullResult): Promise<{ status: FullResult['status'] } | undefined> {
    const rows = SCENARIOS.map((s) => ({ ...s, status: this.statusOf(s.id) }))
    const passed = rows.filter((r) => r.status === 'passed').length
    const ratio = passed / rows.length
    const ok = ratio >= this.threshold && this.unknownIds.size === 0

    mkdirSync(dirname(this.outputFile), { recursive: true })
    writeFileSync(this.outputFile, this.renderHtml(rows, passed, ratio, ok))
    writeFileSync(
      this.outputFile.replace(/\.html$/, '.json'),
      JSON.stringify({ total: rows.length, passed, ratio, threshold: this.threshold, rows }, null, 2),
    )

    const pct = (ratio * 100).toFixed(1)
    console.log(
      `\nシナリオ網羅率: ${passed}/${rows.length} (${pct}%) / 合格ライン ${this.threshold * 100}% → ${ok ? '合格' : '不合格'}`
      + `\nレポート: ${this.outputFile}`,
    )
    if (this.unknownIds.size > 0) {
        console.log(`カタログに無いシナリオID: ${[...this.unknownIds].join(', ')}`)
    }

    // テスト自体が通っていても、網羅率が足りなければ全体を失敗にする。
    // フィルタ実行（--grep 等）では一部のシナリオしか動かないため、全件実行時のみ判定する
    const isFullRun = this.results.size >= rows.length * 0.5
    if (!ok && isFullRun && result.status === 'passed') return { status: 'failed' }
    return undefined
  }

  private renderHtml(
    rows: Array<{ id: string; area: string; title: string; status: Status }>,
    passed: number, ratio: number, ok: boolean,
  ) {
    const label: Record<Status, string> = {
      passed: '合格', failed: '失敗', skipped: 'スキップ', missing: '未実装',
    }
    const areas = [...new Set(rows.map((r) => r.area))]
    const areaRows = areas.map((area) => {
      const inArea = rows.filter((r) => r.area === area)
      const p = inArea.filter((r) => r.status === 'passed').length
      const items = inArea.map((r) => `
        <tr class="${r.status}">
          <td class="id">${escapeHtml(r.id)}</td>
          <td>${escapeHtml(r.title)}</td>
          <td class="st">${label[r.status]}</td>
        </tr>`).join('')
      return `
      <section>
        <h2>${escapeHtml(area)} <small>${p} / ${inArea.length}</small></h2>
        <table><tbody>${items}</tbody></table>
      </section>`
    }).join('')

    return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>E2E シナリオ網羅率</title>
<style>
  :root { color-scheme: light dark; --ok:#15803d; --ng:#b91c1c; --warn:#b45309; --line:#8884; }
  body { font: 14px/1.6 system-ui, "Noto Sans JP", sans-serif; max-width: 960px; margin: 24px auto; padding: 0 16px; }
  h1 { margin: 0 0 8px; font-size: 22px; }
  .summary { display: flex; flex-wrap: wrap; gap: 16px; align-items: center; margin: 12px 0 24px; }
  .big { font-size: 40px; font-weight: 700; color: ${ok ? 'var(--ok)' : 'var(--ng)'}; }
  .bar { flex: 1; min-width: 200px; height: 14px; border-radius: 7px; background: var(--line); overflow: hidden; }
  .bar > span { display: block; height: 100%; width: ${(ratio * 100).toFixed(1)}%; background: ${ok ? 'var(--ok)' : 'var(--ng)'}; }
  h2 { font-size: 16px; margin: 24px 0 6px; } h2 small { color: gray; font-weight: 400; }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 5px 8px; border-bottom: 1px solid var(--line); }
  td.id { width: 80px; font-family: ui-monospace, monospace; }
  td.st { width: 80px; text-align: center; font-weight: 600; }
  tr.passed td.st { color: var(--ok); } tr.failed td.st { color: var(--ng); }
  tr.missing td.st, tr.skipped td.st { color: var(--warn); }
  .note { color: gray; font-size: 12px; }
</style>
</head>
<body>
  <h1>E2E シナリオ網羅率</h1>
  <p class="note">画面・機能・状態遷移のシナリオカタログ（e2e/support/scenarios.ts）のうち、E2Eテストが合格したシナリオの割合です。</p>
  <div class="summary">
    <div class="big">${(ratio * 100).toFixed(1)}%</div>
    <div>${passed} / ${rows.length} シナリオ合格<br>合格ライン ${(this.threshold * 100).toFixed(0)}% → <strong>${ok ? '合格' : '不合格'}</strong></div>
    <div class="bar" role="progressbar" aria-valuenow="${(ratio * 100).toFixed(1)}" aria-valuemin="0" aria-valuemax="100"><span></span></div>
  </div>
  ${areaRows}
  <p class="note"><a href="index.html">Playwright HTMLレポート（テスト別の詳細・トレース）へ</a></p>
</body>
</html>`
  }
}
