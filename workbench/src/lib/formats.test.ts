import { describe, it, expect } from 'vitest'
import { rehydrateFile, survivingValues, validateEntityMap } from './formats'

function blobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result))
    reader.onerror = () => reject(reader.error)
    reader.readAsText(blob)
  })
}

describe('validateEntityMap', () => {
  it('accepts placeholder-string maps', () => {
    expect(validateEntityMap({ '<EMAIL_001>': 'alice@example.test' })).toEqual({
      '<EMAIL_001>': 'alice@example.test',
    })
  })

  it('rejects arbitrary replacement keys', () => {
    expect(() => validateEntityMap({ e: 'X' })).toThrow(/invalid placeholder key/)
  })

  it('rejects non-string replacement values', () => {
    expect(() => validateEntityMap({ '<EMAIL_001>': 42 })).toThrow(/non-string value/)
  })
})

describe('survivingValues', () => {
  it('reports original values that survive in redacted text', () => {
    expect(survivingValues('Contact <EMAIL_001>, not alice@example.test.', [
      'alice@example.test',
      'alice@example.test',
      '',
      'bob@example.test',
    ])).toEqual(['alice@example.test'])
  })

  it('returns empty when every original value is absent', () => {
    expect(survivingValues('Contact <EMAIL_001>.', ['alice@example.test'])).toEqual([])
  })
})

describe('rehydrateFile', () => {
  it('restores text placeholders with a valid map', async () => {
    const file = { name: 'redacted.txt', text: async () => 'Contact <EMAIL_001>.' } as File
    const result = await rehydrateFile(file, { '<EMAIL_001>': 'alice@example.test' })

    expect(result.restored).toBe(1)
    expect(result.unknown).toEqual([])
    expect(result.filename).toBe('restored.txt')
    await expect(blobText(result.blob)).resolves.toBe('Contact alice@example.test.')
  })

  it('uses a neutral restored filename instead of echoing the uploaded name', async () => {
    const file = { name: 'redacted-alice@example.test-client.txt', text: async () => '<EMAIL_001>' } as File
    const result = await rehydrateFile(file, { '<EMAIL_001>': 'alice@example.test' })

    expect(result.filename).toBe('restored.txt')
    expect(result.filename).not.toContain('alice@example.test')
  })

  it('rejects malformed maps before arbitrary text replacement can happen', async () => {
    const file = { name: 'redacted.txt', text: async () => 'Every letter e must remain untouched.' } as File

    await expect(rehydrateFile(file, { e: 'X' })).rejects.toThrow(/invalid placeholder key/)
  })

  it('rejects incomplete maps instead of partially restoring a possible wrong map', async () => {
    const file = {
      name: 'redacted.txt',
      text: async () => 'Contact <EMAIL_001> or call <PHONE_NUMBER_001>.',
    } as File

    await expect(rehydrateFile(file, { '<EMAIL_001>': 'alice@example.test' })).rejects.toThrow(
      /does not resolve 1 placeholder/,
    )
  })
})
