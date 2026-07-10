// Rehydrate component race tests. Files and maps are synthetic; no real PII, no network.

import React, { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Rehydrate from './Rehydrate'
import type * as Formats from '../lib/formats'

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

type Deferred<T> = {
  promise: Promise<T>
  resolve: (value: T) => void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((res) => {
    resolve = res
  })
  return { promise, resolve }
}

const records = {
  a: {
    id: 'fp:A <EMAIL_001>',
    createdAt: 0,
    neutralLabel: 'map A',
    fpExact: 'fp:A <EMAIL_001>',
    placeholders: ['<EMAIL_001>'],
    map: { '<EMAIL_001>': 'alice@example.test' },
  },
  b: {
    id: 'fp:B <EMAIL_001>',
    createdAt: 0,
    neutralLabel: 'map B',
    fpExact: 'fp:B <EMAIL_001>',
    placeholders: ['<EMAIL_001>'],
    map: { '<EMAIL_001>': 'bob@example.test' },
  },
}

vi.mock('../lib/mapStore', () => ({
  sha256Hex: vi.fn(async (body: string) => `fp:${body}`),
  matchByFingerprint: vi.fn(async (fpExact: string) => {
    if (fpExact === records.a.fpExact) return records.a
    if (fpExact === records.b.fpExact) return records.b
    return null
  }),
}))

vi.mock('../lib/formats', async (importOriginal) => {
  const actual = await importOriginal<typeof Formats>()
  return {
    ...actual,
    rehydrateFile: vi.fn(async () => ({ blob: new Blob(['restored']), filename: 'restored.txt', restored: 1 })),
    downloadBlob: vi.fn(),
  }
})

function syntheticFile(name: string, text: () => Promise<string>): File {
  return {
    name,
    text,
  } as unknown as File
}

async function choose(input: HTMLInputElement, file: File): Promise<void> {
  Object.defineProperty(input, 'files', { value: [file], configurable: true })
  await act(async () => {
    input.dispatchEvent(new Event('change', { bubbles: true }))
  })
}

describe('Rehydrate auto-match', () => {
  let host: HTMLDivElement
  let root: Root

  beforeEach(async () => {
    host = document.createElement('div')
    document.body.appendChild(host)
    root = createRoot(host)
    await act(async () => {
      root.render(React.createElement(Rehydrate))
    })
  })

  afterEach(async () => {
    await act(async () => {
      root.unmount()
    })
    host.remove()
  })

  it('ignores stale auto-match results from a previously selected file', async () => {
    const slowA = deferred<string>()
    const fileA = syntheticFile('a.txt', () => slowA.promise)
    const fileB = syntheticFile('b.txt', async () => 'B <EMAIL_001>')
    const input = host.querySelector('input[type="file"]') as HTMLInputElement

    await choose(input, fileA)
    await choose(input, fileB)
    await act(async () => {
      await Promise.resolve()
    })

    expect(host.textContent).toContain('map B')
    expect(host.textContent).not.toContain('map A')

    slowA.resolve('A <EMAIL_001>')
    await act(async () => {
      await slowA.promise
      await Promise.resolve()
    })

    expect(host.textContent).toContain('map B')
    expect(host.textContent).not.toContain('map A')
  })
})
