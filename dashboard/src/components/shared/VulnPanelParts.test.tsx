import { describe, it, expect } from 'vitest'
import * as parts from './VulnPanelParts'

// VulnPanelParts.tsx は Badge.tsx・ChartParts.tsx・TableControls.tsx を
// re-export するバーレルファイル。各ファイル自体の挙動は Badge.test.tsx・
// ChartParts.test.tsx・TableControls.test.tsx でテスト済みのため、ここでは
// 既存の呼び出し元が参照する主要シンボルが barrel 経由でも壊れずに見える
// ことのみ確認する。
describe('shared/VulnPanelParts (barrel re-export)', () => {
  it('re-exports Badge/Chart/TableControls components', () => {
    expect(parts.SeverityBadge).toBeTypeOf('function')
    expect(parts.ChartCard).toBeTypeOf('function')
    expect(parts.SeverityPieChart).toBeTypeOf('function')
    expect(parts.MonthlyBarChart).toBeTypeOf('function')
    expect(parts.TableLoadingSkeleton).toBeTypeOf('function')
    expect(parts.EmptyState).toBeTypeOf('function')
    expect(parts.Pagination).toBeTypeOf('function')
    expect(parts.SeverityFilterButtons).toBeTypeOf('function')
    expect(parts.SearchBox).toBeTypeOf('function')
    expect(parts.SortSelector).toBeTypeOf('function')
  })
})
