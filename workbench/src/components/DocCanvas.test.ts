// Text-view redaction pinning tests. Synthetic strings only; no real PII.

import React, { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'
import DocCanvas from './DocCanvas'
import { pinnedRedactionText } from '../lib/redactionDisplay'

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

function span(id: string, start: number, end: number, active: boolean) {
  return { id, start, end, label: 'person', tier: 0, conf: 0.99, rule: 'test', source: 'manual' as const, active }
}

async function renderDocCanvas(props: React.ComponentProps<typeof DocCanvas>): Promise<{ host: HTMLDivElement; root: Root }> {
  const host = document.createElement('div')
  document.body.appendChild(host)
  const root = createRoot(host)
  await act(async () => {
    root.render(React.createElement(DocCanvas, props))
  })
  return { host, root }
}

async function cleanupRender(root: Root, host: HTMLDivElement): Promise<void> {
  await act(async () => {
    root.unmount()
  })
  host.remove()
}

describe('pinnedRedactionText', () => {
  it('masks every non-whitespace code unit without changing the string length', () => {
    const original = 'Alice Smith\tQC'
    const masked = pinnedRedactionText(original)

    expect(masked).toBe('█████ █████\t██')
    expect(masked).toHaveLength(original.length)
  })

  it('preserves spaces, tabs, and newlines so masked text occupies the original text positions', () => {
    const original = 'Line one\nLine\ttwo'
    const masked = pinnedRedactionText(original)

    expect(masked).toBe('████ ███\n████\t███')
    expect(masked).toHaveLength(original.length)
    expect(masked[8]).toBe('\n')
    expect(masked[13]).toBe('\t')
  })
})

describe('DocCanvas redaction pinning', () => {
  it('renders active text-view spans as same-length masks and inactive spans as their original text', async () => {
    const activeValue = 'Alice\nSmith'
    const inactiveValue = 'Bob Jones'
    const text = `Hide ${activeValue} but keep ${inactiveValue}.`
    const activeStart = text.indexOf(activeValue)
    const inactiveStart = text.indexOf(inactiveValue)
    const placeholderOf = new Map([
      ['active-person', '<PERSON_001>'],
      ['kept-person', '<PERSON_002>'],
    ])
    const { host, root } = await renderDocCanvas({
      text,
      spans: [
        span('active-person', activeStart, activeStart + activeValue.length, true),
        span('kept-person', inactiveStart, inactiveStart + inactiveValue.length, false),
      ],
      placeholderOf,
      selectedId: null,
      onSelect: vi.fn(),
      onAddManual: vi.fn(),
    })

    try {
      const activeChip = host.querySelector('.tok-active') as HTMLElement | null
      const inactiveChip = host.querySelector('.tok-inactive') as HTMLElement | null

      expect(activeChip?.textContent).toBe('█████\n█████')
      expect(activeChip?.textContent).toHaveLength(activeValue.length)
      expect(activeChip?.textContent).not.toBe(placeholderOf.get('active-person'))
      expect(activeChip?.textContent).not.toContain('Alice')
      expect(activeChip?.textContent).not.toContain('Smith')
      expect(activeChip?.style.padding).toBe('0px')
      expect(activeChip?.style.fontSize).toBe('1em')
      expect(activeChip?.style.fontFamily).toBe('inherit')
      expect(activeChip?.style.fontWeight).toBe('inherit')

      expect(inactiveChip?.textContent).toBe(inactiveValue)
      expect(inactiveChip?.style.fontFamily).toBe('inherit')
      expect(inactiveChip?.style.fontWeight).toBe('inherit')
      expect(host.textContent).toContain(inactiveValue)
      expect(host.textContent).not.toContain('<PERSON_001>')
    } finally {
      await cleanupRender(root, host)
    }
  })
})
