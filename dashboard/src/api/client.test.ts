import { describe, it, expect } from 'vitest'
import * as client from './client'

// client.ts はドメインごとに分割された各モジュール（shared/kev/osv/jvn/depscan/
// depsops/crawlerLogs/auth）を re-export するバーレルファイル。各モジュール自体の
// 挙動は kev.test.ts・osv.test.ts・jvn.test.ts・depscan.test.ts・depsops.test.ts・
// crawlerLogs.test.ts・auth.test.ts・shared.test.ts でテスト済みのため、ここでは
// 既存の呼び出し元が参照する主要シンボルが barrel 経由でも壊れずに見えることのみ確認する。
describe('api/client (barrel re-export)', () => {
  it('re-exports the KEV/OSV/JVN/DEPSCAN/DEPSOPS/crawlerLogs/auth API surface', () => {
    expect(client.fetchHealth).toBeTypeOf('function')
    expect(client.fetchRecent).toBeTypeOf('function')
    expect(client.fetchStats).toBeTypeOf('function')
    expect(client.fetchVulnerabilities).toBeTypeOf('function')
    expect(client.fetchOsvList).toBeTypeOf('function')
    expect(client.fetchOsvStats).toBeTypeOf('function')
    expect(client.fetchJvnList).toBeTypeOf('function')
    expect(client.fetchJvnStats).toBeTypeOf('function')
    expect(client.fetchDepscanList).toBeTypeOf('function')
    expect(client.fetchDepscanStats).toBeTypeOf('function')
    expect(client.fetchAllDepscanFindings).toBeTypeOf('function')
    expect(client.fetchDepsOpsList).toBeTypeOf('function')
    expect(client.fetchDepsOpsStats).toBeTypeOf('function')
    expect(client.fetchCrawlerLogs).toBeTypeOf('function')
    expect(client.githubLoginUrl).toBeTypeOf('function')
    expect(client.fetchScanStatus).toBeTypeOf('function')
    expect(client.exchangeAuthCode).toBeTypeOf('function')
    expect(client.UnauthorizedError).toBeTypeOf('function')
  })
})
