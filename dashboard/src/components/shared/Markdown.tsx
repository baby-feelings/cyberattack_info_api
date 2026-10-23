import type { ReactNode } from 'react'
import { parseMarkdown, type Block, type Inline } from './parseMarkdown'

// 文の中の記法（コード・強調・リンク）を、React の要素に変換する
function renderInline(nodes: Inline[]): ReactNode[] {
  return nodes.map((node, i) => {
    switch (node.type) {
      case 'text':
        return node.text
      case 'code':
        return (
          <code key={i} className="px-1 rounded bg-slate-950 text-slate-300 font-mono text-[11px] break-all">
            {node.text}
          </code>
        )
      case 'strong':
        return <strong key={i} className="font-semibold text-slate-300">{renderInline(node.children)}</strong>
      case 'em':
        return <em key={i}>{renderInline(node.children)}</em>
      case 'link':
        return (
          <a
            key={i}
            href={node.href}
            target="_blank"
            rel="noopener noreferrer"
            className="text-violet-400 hover:text-violet-300 underline underline-offset-2 break-all"
          >
            {renderInline(node.children)}
          </a>
        )
    }
  })
}

const HEADING_CLS: Record<number, string> = {
  1: 'text-sm font-semibold text-slate-200',
  2: 'text-sm font-semibold text-slate-200',
  3: 'text-xs font-semibold text-slate-200',
}

function renderBlock(block: Block, key: number): ReactNode {
  switch (block.type) {
    case 'heading':
      return (
        <p key={key} role="heading" aria-level={block.level} className={`${HEADING_CLS[block.level] ?? 'text-xs font-semibold text-slate-300'} pt-1`}>
          {renderInline(block.children)}
        </p>
      )
    case 'paragraph':
      return <p key={key} className="leading-relaxed">{renderInline(block.children)}</p>
    case 'code':
      return (
        <pre key={key} className="bg-slate-950 rounded p-2 overflow-x-auto text-[11px] text-slate-300">
          {block.text}
        </pre>
      )
    case 'list': {
      const Tag = block.ordered ? 'ol' : 'ul'
      return (
        <Tag key={key} className={`${block.ordered ? 'list-decimal' : 'list-disc'} pl-5 space-y-0.5`}>
          {block.items.map((item, i) => <li key={i} className="leading-relaxed">{renderInline(item)}</li>)}
        </Tag>
      )
    }
    case 'quote':
      return (
        <blockquote key={key} className="border-l-2 border-slate-600 pl-3 text-slate-500 space-y-2">
          {block.blocks.map(renderBlock)}
        </blockquote>
      )
    case 'table':
      return (
        // 幅の広い表は、表の中だけ横にスクロールできるようにする
        <div key={key} className="overflow-x-auto">
          <table className="text-[11px] border-collapse">
            <thead>
              <tr>
                {block.header.map((cell, i) => (
                  <th key={i} className="border border-slate-700 px-2 py-1 text-left font-semibold text-slate-300">
                    {renderInline(cell)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {block.rows.map((row, r) => (
                <tr key={r}>
                  {row.map((cell, c) => (
                    <td key={c} className="border border-slate-700 px-2 py-1">{renderInline(cell)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
    case 'rule':
      return <hr key={key} className="border-slate-700" />
  }
}

// 外部データのマークダウン（OSV の詳細など）を表示する。HTML として埋め込まず、要素に変換するため、
// 本文に <script> や onerror= のような文字列があっても、ただの文字として表示される
export function Markdown({ source }: { source: string }) {
  return <div className="space-y-2 break-words">{parseMarkdown(source).map(renderBlock)}</div>
}
