import '@testing-library/jest-dom/vitest'

// jsdom には ResizeObserver が実装されていないため、recharts の
// ResponsiveContainer がエラーにならないよう最小限のモックを用意する
class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = ResizeObserverMock
