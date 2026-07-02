// Pure-function assertions for the Connect tab's snippet generator -- no React rendering, no network.
import { describe, it, expect } from 'vitest'
import { connectSnippets } from './ConnectPanel'

describe('connectSnippets', () => {
  it('substitutes the given base into the Claude Code and Codex blocks', () => {
    const snips = connectSnippets('http://127.0.0.1:8011')
    const claude = snips.find((s) => s.id === 'claude-code')!
    expect(claude.code).toContain('export ANTHROPIC_BASE_URL=http://127.0.0.1:8011')
    // The dead _CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL export must NOT come back (probe-verified
    // inert on CC 2.1.197); the [1m] model suffix is what sizes the bar to the true 1M window.
    expect(claude.code).not.toContain('_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL')
    expect(claude.code).toContain("claude --model 'claude-fable-5[1m]'")

    const codex = snips.find((s) => s.id === 'codex')!
    expect(codex.code).toContain('base_url = "http://127.0.0.1:8011/v1"')
    expect(codex.code).toContain('wire_api = "responses"')
  })

  it('honors a non-default base (Tauri/hosted) and strips a trailing slash', () => {
    const snips = connectSnippets('http://127.0.0.1:9000/')
    const claude = snips.find((s) => s.id === 'claude-code')!
    expect(claude.code).toContain('ANTHROPIC_BASE_URL=http://127.0.0.1:9000')
    expect(claude.code).not.toContain('9000/') // trailing slash stripped, no //v1 either
    const codex = snips.find((s) => s.id === 'codex')!
    expect(codex.code).toContain('base_url = "http://127.0.0.1:9000/v1"')
  })

  it('covers Claude Code, Codex, and a generic SDK path', () => {
    const ids = connectSnippets('http://127.0.0.1:8011').map((s) => s.id)
    expect(ids).toContain('claude-code')
    expect(ids).toContain('codex')
    expect(ids).toContain('anthropic-sdk')
  })
})
