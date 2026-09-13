// OsvPanel・JvnPanel で共有する、脆弱性一覧パネルの汎用パーツ群のバーレルファイル。
//
// 実装は Badge系（Badge.tsx）・Chart系（ChartParts.tsx）・テーブル制御系
// （TableControls.tsx）の3ファイルに分割されている。既存の呼び出し元が
// `import { xxx } from '../shared/VulnPanelParts'` のまま動き続けるよう、
// ここで re-export する。深刻度の値・配色・件数などドメイン固有の情報は
// 引き続き呼び出し側から props で渡す。

export * from './Badge'
export * from './ChartParts'
export * from './TableControls'
