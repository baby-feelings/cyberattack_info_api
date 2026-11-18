// アプリのロゴ（public/favicon.svg と同じ絵: 盾・チェック・赤い通知点）。
// 色は絵の一部なので、ここに固定で持つ（画面のテーマ色とは独立）。
const LOGO_COLORS = { shield: '#6d5ce6', check: '#ffffff', dot: '#ef4444', ring: '#0a0e1a' } as const

interface AppLogoProps {
  /** 一辺の大きさ（px） */
  size?: number
}

export function AppLogo({ size = 32 }: AppLogoProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 160 160" aria-hidden="true" focusable="false" className="shrink-0">
      <path
        d="M80 22 L128 40 V82 C128 110 108 128 80 140 C52 128 32 110 32 82 V40 Z"
        fill={LOGO_COLORS.shield}
      />
      <polyline
        points="56,84 74,102 106,66"
        fill="none"
        stroke={LOGO_COLORS.check}
        strokeWidth={10}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="122" cy="40" r="15" fill={LOGO_COLORS.dot} stroke={LOGO_COLORS.ring} strokeWidth={5} />
    </svg>
  )
}
