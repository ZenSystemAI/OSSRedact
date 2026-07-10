// App batch-export regression. Files and detector results are synthetic; no network or model load.

import React, { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest'
import type * as Formats from './lib/formats'
import type * as Gate from './lib/gate'
import type * as Neural from './lib/neural'
import { DEEP_DEGRADED_EXPORT_CONFIRM } from './lib/degrade'
import App from './App'

const prepareDeepDetectMock = vi.hoisted(() => vi.fn())
const deepDetectMock = vi.hoisted(() => vi.fn())
const downloadBlobMock = vi.hoisted(() => vi.fn())
const clipboardWriteTextMock = vi.hoisted(() => vi.fn(async () => undefined))

vi.mock('./lib/gate', async (importOriginal) => {
  const actual = await importOriginal<typeof Gate>()
  return {
    ...actual,
    prepareDeepDetect: prepareDeepDetectMock,
    deepDetect: deepDetectMock,
  }
})

vi.mock('./lib/neural', async (importOriginal) => {
  const actual = await importOriginal<typeof Neural>()
  return {
    ...actual,
    modelOnDevice: vi.fn(async () => true),
  }
})

vi.mock('./lib/formats', async (importOriginal) => {
  const actual = await importOriginal<typeof Formats>()
  return {
    ...actual,
    downloadBlob: downloadBlobMock,
  }
})

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

type Deferred<T> = {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason: unknown) => void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

function syntheticTextFile(name: string, text: string): File {
  return {
    name,
    text: vi.fn(async () => text),
  } as unknown as File
}

async function flushAsyncWork(): Promise<void> {
  await Promise.resolve()
  await Promise.resolve()
  await Promise.resolve()
}

async function chooseFiles(input: HTMLInputElement, files: File[]): Promise<void> {
  Object.defineProperty(input, 'files', { value: files, configurable: true })
  await act(async () => {
    input.dispatchEvent(new Event('change', { bubbles: true }))
    await flushAsyncWork()
  })
}

function buttonNamed(host: HTMLElement, label: string): HTMLButtonElement {
  const button = Array.from(host.querySelectorAll('button')).find((candidate) => candidate.textContent?.trim() === label)
  if (!button) throw new Error(`Expected ${label} button to be rendered`)
  return button
}

function menuItemNamed(host: HTMLElement, label: string): HTMLButtonElement {
  const item = Array.from(host.querySelectorAll<HTMLButtonElement>('[role="menuitem"]')).find((candidate) => candidate.textContent?.includes(label))
  if (!item) throw new Error(`Expected ${label} menu item to be rendered`)
  return item
}

async function waitFor(condition: () => boolean, description: string): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (condition()) return
    await act(async () => {
      await flushAsyncWork()
    })
  }
  throw new Error(`Timed out waiting for ${description}`)
}

describe('App batch deep-scan export gate', () => {
  let host: HTMLDivElement
  let root: Root
  let confirmSpy: MockInstance<(message?: string) => boolean>
  let clipboardDescriptor: PropertyDescriptor | undefined


  beforeEach(async () => {
    vi.clearAllMocks()
    prepareDeepDetectMock.mockReset()
    deepDetectMock.mockReset()
    clipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, 'clipboard')
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: clipboardWriteTextMock },
    })

    host = document.createElement('div')
    document.body.appendChild(host)
    root = createRoot(host)
    confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false)

    await act(async () => {
      root.render(React.createElement(App))
    })
  })

  afterEach(async () => {
    await act(async () => {
      root.unmount()
    })
    host.remove()
    if (clipboardDescriptor) Object.defineProperty(navigator, 'clipboard', clipboardDescriptor)
    else Reflect.deleteProperty(navigator, 'clipboard')

    vi.restoreAllMocks()
  })

  async function loadCancelledBatch(): Promise<void> {
    const provider = deferred<'gateway'>()
    prepareDeepDetectMock.mockReturnValueOnce(provider.promise)
    const input = host.querySelector('input[type="file"]') as HTMLInputElement

    await chooseFiles(input, [
      syntheticTextFile('first.txt', 'Contact demo.one@example.test for the review.'),
      syntheticTextFile('second.txt', 'Contact demo.two@example.test for the review.'),
    ])
    await waitFor(() => host.textContent?.includes('Batch: 2 txt files') ?? false, 'the batch to load')

    await act(async () => {
      buttonNamed(host, 'Deep detect all').click()
      await flushAsyncWork()
    })
    await waitFor(() => prepareDeepDetectMock.mock.calls.length === 1, 'deep-provider preparation')

    await act(async () => {
      buttonNamed(host, 'Cancel').click()
      provider.reject(new DOMException('cancelled', 'AbortError'))
      await flushAsyncWork()
    })
    await waitFor(
      () => host.textContent?.includes('Deep detect was cancelled before every file finished.') ?? false,
      'the partial batch status',
    )
    expect(host.textContent).toContain('#02 · pending')

    await act(async () => {
      buttonNamed(host, 'Auto-detect').click()
      await flushAsyncWork()
    })
  }

  it('keeps a cancelled batch export confirmation after a single-document auto-detect leaves another entry pending', async () => {
    await loadCancelledBatch()

    await act(async () => {
      buttonNamed(host, 'Download batch (.zip)').click()
      await flushAsyncWork()
    })

    expect(confirmSpy).toHaveBeenCalledTimes(1)
    expect(confirmSpy).toHaveBeenCalledWith(DEEP_DEGRADED_EXPORT_CONFIRM)
    expect(downloadBlobMock).not.toHaveBeenCalled()
  })

  it('requires confirmation before the active file leaves a cancelled batch after auto-detect resets its deep status', async () => {
    await loadCancelledBatch()

    await act(async () => {
      buttonNamed(host, 'Export').click()
      await flushAsyncWork()
    })
    await act(async () => {
      menuItemNamed(host, 'Copy redacted text').click()
      await flushAsyncWork()
    })

    expect(confirmSpy).toHaveBeenCalledWith(DEEP_DEGRADED_EXPORT_CONFIRM)
    expect(clipboardWriteTextMock).not.toHaveBeenCalled()
  })

  it('requires confirmation before printing the active file from a cancelled batch after auto-detect resets its deep status', async () => {
    await loadCancelledBatch()
    const printSpy = vi.spyOn(window, 'print').mockImplementation(() => undefined)

    await act(async () => {
      buttonNamed(host, 'Print').click()
      await flushAsyncWork()
    })

    expect(confirmSpy).toHaveBeenCalledWith(DEEP_DEGRADED_EXPORT_CONFIRM)
    expect(printSpy).not.toHaveBeenCalled()
  })

  it('requires confirmation before downloading a batch when the active document deep scan degrades while batch scanning remains unstarted', async () => {
    prepareDeepDetectMock.mockResolvedValueOnce('gateway')
    deepDetectMock.mockRejectedValueOnce(new Error('synthetic deep-provider failure'))
    const input = host.querySelector('input[type="file"]') as HTMLInputElement

    await chooseFiles(input, [
      syntheticTextFile('first.txt', 'Contact demo.one@example.test for the review.'),
      syntheticTextFile('second.txt', 'Contact demo.two@example.test for the review.'),
    ])
    await waitFor(() => host.textContent?.includes('Batch: 2 txt files') ?? false, 'the batch to load')

    await act(async () => {
      buttonNamed(host, 'Deep detect').click()
      await flushAsyncWork()
    })
    await waitFor(
      () => host.textContent?.includes('Deep detect unavailable -- using local Tier-0 only. (synthetic deep-provider failure)') ?? false,
      'the active deep scan to degrade',
    )
    expect(host.textContent).toContain(
      'Structured data only (secrets, IDs, cards, emails, dates). Names, organizations, and addresses are NOT scanned until you run Deep detect.',
    )

    await act(async () => {
      buttonNamed(host, 'Download batch (.zip)').click()
      await flushAsyncWork()
    })

    expect(confirmSpy).toHaveBeenCalledWith(DEEP_DEGRADED_EXPORT_CONFIRM)
    expect(downloadBlobMock).not.toHaveBeenCalled()
  })
})
