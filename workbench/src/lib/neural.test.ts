// Tests for browser-model runtime wiring. No model is loaded and no network is touched.

import { beforeEach, describe, expect, it, vi } from 'vitest'

const hf = vi.hoisted(() => {
  const env = {
    allowRemoteModels: true,
    allowLocalModels: false,
    localModelPath: '',
    backends: { onnx: { wasm: { wasmPaths: '', numThreads: 4 } } },
  }
  const tokenizer = Object.assign(vi.fn(async () => ({})), {
    tokenize: vi.fn((): string[] => []),
  })
  const model = Object.assign(vi.fn(async () => ({ logits: { tolist: () => [[]] } })), {
    config: { id2label: { 0: 'O' } },
  })
  return {
    env,
    tokenizer,
    model,
    tokenizerFrom: vi.fn(async () => tokenizer),
    modelFrom: vi.fn(async () => model),
  }
})

vi.mock('@huggingface/transformers', () => ({
  env: hf.env,
  AutoTokenizer: { from_pretrained: hf.tokenizerFrom },
  AutoModelForTokenClassification: { from_pretrained: hf.modelFrom },
}))

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()
  hf.env.allowRemoteModels = true
  hf.env.allowLocalModels = false
  hf.env.localModelPath = ''
  hf.env.backends.onnx.wasm.wasmPaths = ''
  hf.env.backends.onnx.wasm.numThreads = 4
})

describe('browser neural runtime', () => {
  it('pins transformers.js to same-origin assets and wasm', async () => {
    const { loadNeural, neuralStatus } = await import('./neural')

    await expect(loadNeural()).resolves.toBeUndefined()

    expect(hf.env.allowRemoteModels).toBe(false)
    expect(hf.env.allowLocalModels).toBe(true)
    expect(hf.env.localModelPath).toBe('/')
    expect(hf.env.backends.onnx.wasm.wasmPaths).toBe('/ort/')
    expect(hf.env.backends.onnx.wasm.numThreads).toBe(1)
    expect(hf.tokenizerFrom).toHaveBeenCalledWith(
      'model',
      expect.objectContaining({ progress_callback: expect.any(Function) }),
    )
    expect(hf.modelFrom).toHaveBeenCalledWith(
      'model',
      expect.objectContaining({
        dtype: 'int8',
        device: 'wasm',
        progress_callback: expect.any(Function),
      }),
    )
    expect(neuralStatus()).toBe('ready')
  })

  it('forwards transformers progress events to the caller', async () => {
    const { loadNeural } = await import('./neural')
    const onProgress = vi.fn()

    await loadNeural(onProgress)
    const calls = hf.tokenizerFrom.mock.calls as unknown as Array<[string, {
      progress_callback: (p: { status: string; progress?: number }) => void
    }]>
    const opts = calls[0][1]
    opts.progress_callback({ status: 'progress', progress: 42 })

    expect(onProgress).toHaveBeenCalledWith({ status: 'progress', progress: 42 })
  })
})
