import { describe, it, expect } from 'vitest'
// Node の fs を使わず、Vite の ?raw で vercel.json を文字列として取り込む（型定義を増やさないため）
import vercelJson from '../vercel.json?raw'

// ダッシュボードの本番ヘッダー（vercel.json）の CSP が、画面が実際に使う外部オリジンを許可していること。
// CSP で外部の画像・通信を許可し忘れると、本番だけ画像が出ない・API に接続できない
// （E2E は同一オリジンのモックで動くため、CSP の不足には気づけない）。

function cspDirectives(): Record<string, string[]> {
  const config = JSON.parse(vercelJson)
  const header = config.headers
    .flatMap((h: { headers: { key: string, value: string }[] }) => h.headers)
    .find((h: { key: string }) => h.key === 'Content-Security-Policy')
  expect(header, 'vercel.json に Content-Security-Policy があること').toBeDefined()
  const directives: Record<string, string[]> = {}
  for (const part of header.value.split(';')) {
    const [name, ...values] = part.trim().split(/\s+/)
    if (name) directives[name] = values
  }
  return directives
}

describe('vercel.json の Content-Security-Policy', () => {
  it('allows the Dependabot compatibility-score badge images (DEPSOPS)', () => {
    // 画像は https://dependabot-badges.githubapp.com/ から読み込む（バックエンドが同ホストのURLだけ保存する）
    expect(cspDirectives()['img-src']).toContain('https://dependabot-badges.githubapp.com')
  })

  it('allows the production API origin for fetch', () => {
    expect(cspDirectives()['connect-src']).toContain('https://168.138.213.240.nip.io')
  })

  it('does not allow inline or external scripts, and forbids framing', () => {
    const directives = cspDirectives()
    expect(directives['script-src']).toEqual(["'self'"])
    expect(directives['frame-ancestors']).toEqual(["'none'"])
    expect(directives['object-src']).toEqual(["'none'"])
  })
})
