// favicon.svg を元に、各サイズの PNG と favicon.ico を生成する（実行: node scripts/generate-icons.mjs）。
// 絵を変えるときは public/favicon.svg だけを直して、このスクリプトを再実行する。
import { chromium } from '@playwright/test'
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const publicDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'public')
const svg = readFileSync(join(publicDir, 'favicon.svg'), 'utf8')
const BG = '#0a0e1a'

// maskable 用: 背景を全面に敷き、絵を中央の安全域（約 70%）へ縮めて、端末の切り抜きで欠けないようにする
const inner = svg.replace(/^[\s\S]*?<svg[^>]*>/, '').replace(/<\/svg>\s*$/, '').replace(/<rect[^>]*\/>/, '')
const maskableSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 160"><rect width="160" height="160" fill="${BG}"/><g transform="translate(24 24) scale(0.7)">${inner}</g></svg>`

// 出力一覧: [ファイル名, SVG, 一辺の px]
const targets = [
  ['favicon-96x96.png', svg, 96],
  ['apple-touch-icon.png', svg.replace(/rx="36"/, 'rx="0"'), 180], // iOS が角を丸めるため、角は付けない
  ['web-app-manifest-192x192.png', maskableSvg, 192],
  ['web-app-manifest-512x512.png', maskableSvg, 512],
]
const icoSizes = [16, 32, 48]

const browser = await chromium.launch()
const page = await browser.newPage()
async function render(source, size) {
  await page.setViewportSize({ width: size, height: size })
  await page.setContent(`<body style="margin:0;background:transparent"><img style="width:${size}px;height:${size}px;display:block" src="data:image/svg+xml;base64,${Buffer.from(source).toString('base64')}"></body>`)
  return page.screenshot({ omitBackground: true, type: 'png' })
}

for (const [name, source, size] of targets) {
  writeFileSync(join(publicDir, name), await render(source, size))
}

// ICO は PNG をそのまま格納する形式で組み立てる
const pngs = []
for (const size of icoSizes) pngs.push([size, await render(svg, size)])
const header = Buffer.alloc(6)
header.writeUInt16LE(1, 2)
header.writeUInt16LE(pngs.length, 4)
let offset = 6 + 16 * pngs.length
const entries = pngs.map(([size, data]) => {
  const e = Buffer.alloc(16)
  e.writeUInt8(size, 0); e.writeUInt8(size, 1)
  e.writeUInt16LE(1, 4); e.writeUInt16LE(32, 6)
  e.writeUInt32LE(data.length, 8); e.writeUInt32LE(offset, 12)
  offset += data.length
  return e
})
writeFileSync(join(publicDir, 'favicon.ico'), Buffer.concat([header, ...entries, ...pngs.map(([, d]) => d)]))
await browser.close()
