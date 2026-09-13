// API クライアント: 本番 API への全リクエストを集約するバーレルファイル。
//
// 実装は KEV/OSV/JVN/DEPSCAN/DEPSOPS の各ドメインモジュール（kev.ts・osv.ts・jvn.ts・
// depscan.ts・depsops.ts）と、クローラーログ（crawlerLogs.ts）・GitHub ログイン
// （auth.ts）・共通部分（shared.ts）に分割されている。既存の呼び出し元
// （各 Panel・コンポーネント）が `import { xxx } from '../api/client'` のまま
// 動き続けるよう、ここで re-export する。

export * from './shared'
export * from './kev'
export * from './osv'
export * from './jvn'
export * from './depscan'
export * from './depsops'
export * from './crawlerLogs'
export * from './auth'
