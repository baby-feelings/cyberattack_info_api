// 系列（"3.14"・"24"）の新旧の比較用。"3.9" < "3.14" になるよう、数として比べる
function cycleKey(cycle: string): number[] {
  return cycle.split('.').map(part => Number(part) || 0)
}

export function isNewerCycle(a: string, b: string): boolean {
  const ka = cycleKey(a)
  const kb = cycleKey(b)
  for (let i = 0; i < Math.max(ka.length, kb.length); i += 1) {
    const diff = (ka[i] ?? 0) - (kb[i] ?? 0)
    if (diff !== 0) return diff > 0
  }
  return false
}
