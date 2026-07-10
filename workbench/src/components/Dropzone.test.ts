// Dropzone regression tests. Files are synthetic; no real PDFs, no network, no timers.

import React, { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import type { LoadedDoc } from '../lib/formats'
import Dropzone from './Dropzone'

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
type LoadHandler = (doc: LoadedDoc) => void
type BatchLoadHandler = (docs: LoadedDoc[]) => void


function syntheticTextFile(name: string, text: string): File {
  return {
    name,
    text: vi.fn(async () => text),
  } as unknown as File
}

function createDropEvent(files: File[]): Event {
  const event = new Event('drop', { bubbles: true, cancelable: true })
  Object.defineProperty(event, 'dataTransfer', {
    value: { files },
    configurable: true,
  })
  return event
}

async function flushAsyncWork(): Promise<void> {
  await Promise.resolve()
  await Promise.resolve()
  await Promise.resolve()
}

async function dispatchDrop(target: EventTarget, files: File[]): Promise<void> {
  await act(async () => {
    target.dispatchEvent(createDropEvent(files))
    await flushAsyncWork()
  })
}

async function choose(input: HTMLInputElement, file: File): Promise<void> {
  Object.defineProperty(input, 'files', { value: [file], configurable: true })
  await act(async () => {
    input.dispatchEvent(new Event('change', { bubbles: true }))
    await flushAsyncWork()
  })
}

describe('Dropzone file loading', () => {
  let host: HTMLDivElement
  let root: Root
  let onLoad: Mock<LoadHandler>
  let onLoadBatch: Mock<BatchLoadHandler>

  beforeEach(async () => {
    host = document.createElement('div')
    document.body.appendChild(host)
    root = createRoot(host)
    onLoad = vi.fn()
    onLoadBatch = vi.fn()

    await act(async () => {
      root.render(React.createElement(Dropzone, { onLoad, onLoadBatch }))
    })
  })

  afterEach(async () => {
    await act(async () => {
      root.unmount()
    })
    host.remove()
  })

  it('loads a file dropped on the document body through the normal file loader path', async () => {
    const file = syntheticTextFile('outside.txt', 'outside drop text')

    await dispatchDrop(document.body, [file])

    expect(onLoad).toHaveBeenCalledTimes(1)
    expect(onLoad).toHaveBeenCalledWith({ name: 'outside.txt', text: 'outside drop text', kind: 'txt' })
    expect(onLoadBatch).not.toHaveBeenCalled()
    expect(file.text).toHaveBeenCalledTimes(1)
  })

  it('loads a panel drop once when the window-level drop listener is mounted', async () => {
    const file = syntheticTextFile('panel.txt', 'panel drop text')
    const panel = host.querySelector('.panel.cursor-pointer')

    expect(panel).toBeInstanceOf(HTMLDivElement)
    await dispatchDrop(panel as HTMLDivElement, [file])

    expect(onLoad).toHaveBeenCalledTimes(1)
    expect(onLoad).toHaveBeenCalledWith({ name: 'panel.txt', text: 'panel drop text', kind: 'txt' })
    expect(onLoadBatch).not.toHaveBeenCalled()
    expect(file.text).toHaveBeenCalledTimes(1)
  })

  it('resets the file input after a change so the same file can be chosen again', async () => {
    const file = syntheticTextFile('repeat.txt', 'repeatable text')
    const input = host.querySelector('input[type="file"]') as HTMLInputElement
    const valueAssignments: string[] = []

    Object.defineProperty(input, 'value', {
      configurable: true,
      get: () => 'C:\\fakepath\\repeat.txt',
      set: (value) => {
        valueAssignments.push(String(value))
      },
    })

    await choose(input, file)
    await choose(input, file)

    expect(valueAssignments).toEqual(['', ''])
    expect(onLoad).toHaveBeenCalledTimes(2)
    expect(onLoad).toHaveBeenNthCalledWith(1, { name: 'repeat.txt', text: 'repeatable text', kind: 'txt' })
    expect(onLoad).toHaveBeenNthCalledWith(2, { name: 'repeat.txt', text: 'repeatable text', kind: 'txt' })
    expect(onLoadBatch).not.toHaveBeenCalled()
    expect(file.text).toHaveBeenCalledTimes(2)
  })
})
