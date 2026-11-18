// 態勢タブのコンポーネントのテストで共有するデータ（テスト専用。アプリの本体からは参照しない）。

import type { AuditCheckOut } from '../../api/client'
import { AlertList } from './model/AlertList'
import { AuditMatrix } from './model/AuditMatrix'
import { RepoAudit } from './model/RepoAudit'
import { SiteCheck } from './model/SiteCheck'
import type { Source } from './usePostureData'

export const ready = <T,>(value: T): Source<T> => ({ status: 'ready', value })
export const loading = <T,>(): Source<T> => ({ status: 'loading' })
export const failed = <T,>(message = 'API error 500'): Source<T> =>
  ({ status: 'error', message, unauthorized: false })
// セッションが無効・期限切れ（401）で、取得できなかった
export const unauthorized = <T,>(): Source<T> =>
  ({ status: 'error', message: 'Session token is invalid or expired', unauthorized: true })

const check = (key: string, label: string, status: string, detail = '', fix = ''): AuditCheckOut =>
  ({ key, label, status, weight: 1, detail, fix })

// alpha: 全部合格（「ブランチ保護」の項目は無い）／beta: 1件不合格・1件は強制できない（「push 保護」の項目は無い）
export function auditMatrix(): AuditMatrix {
  return new AuditMatrix([
    new RepoAudit({
      repo_full_name: 'owner/alpha', score: 100, issues: 0, changes: [], audited_at: '2026-11-18T00:00:00Z',
      checks: [check('secret_scanning', 'シークレットスキャン', 'ok'), check('push_protection', 'push 保護', 'ok')],
    }),
    new RepoAudit({
      repo_full_name: 'owner/beta', score: 50, issues: 1, changes: [], audited_at: '2026-11-18T00:00:00Z',
      checks: [
        check('secret_scanning', 'シークレットスキャン', 'ng', '無効になっています', '設定の「セキュリティ」で有効にする'),
        check('branch_protection', 'ブランチ保護', 'not_enforceable', '非公開の無料リポジトリです'),
      ],
    }),
  ])
}

export function alertList(): AlertList {
  const base = { detected_at: '2026-11-18T00:00:00Z', resolved_at: null }
  return AlertList.fromResponse({
    total: 3,
    data: [
      { ...base, kind: 'dependabot', repo_full_name: 'owner/alpha', number: 3, severity: 'MEDIUM', title: 'lodash の脆弱性',
        html_url: 'javascript:alert(1)', detail: {} },
      { ...base, kind: 'secret', repo_full_name: 'owner/beta', number: 1, severity: 'CRITICAL', title: 'AWS のキー',
        html_url: 'https://github.com/owner/beta/security/secret-scanning/1', detail: {} },
      { ...base, kind: 'code', repo_full_name: 'owner/alpha', number: 2, severity: 'HIGH', title: 'XSS の可能性',
        html_url: 'https://github.com/owner/alpha/security/code-scanning/2', detail: { tool: 'CodeQL' } },
    ],
    unavailable: [{ kind: 'secret', repo_full_name: 'owner/web', reason: 'HTTP 404' }],
  })
}

export function sites(): SiteCheck[] {
  const base = { source: 'homepage', checked_at: '2026-11-18T00:00:00Z' }
  return [
    new SiteCheck({ ...base, url: 'https://bad.example', repo_full_name: 'owner/alpha', tls_days_left: 3, issues: 1,
      findings: [{ rule: 'tls-expiring', severity: 'ERROR', message: 'TLS 証明書の期限が、あと3日です' }] }),
    new SiteCheck({ ...base, url: 'https://ok.example', repo_full_name: null, tls_days_left: 90, issues: 0, findings: [] }),
  ]
}
