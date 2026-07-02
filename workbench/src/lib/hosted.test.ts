import { describe, expect, it } from 'vitest'
import { isHostedDemo, HOSTED_DOC_BASE } from './hosted'

// The hosted-demo check decides whether the console renders the gate-connection form (operator
// trust domain) or the read-only funnel (public site). Getting it wrong either re-opens the
// "public origin can hold a gate's controls" hole or breaks self-hosted/loopback consoles.
describe('isHostedDemo', () => {
  it('matches the product site and its subdomains', () => {
    expect(isHostedDemo('ossredact.dev')).toBe(true)
    expect(isHostedDemo('www.ossredact.dev')).toBe(true)
    expect(isHostedDemo('OSSREDACT.DEV')).toBe(true)
  })

  it('matches Vercel preview deploys', () => {
    expect(isHostedDemo('ossredact-web-git-main.vercel.app')).toBe(true)
  })

  it('does NOT match lookalike suffixes (no substring match)', () => {
    expect(isHostedDemo('evilossredact.dev')).toBe(false)
    expect(isHostedDemo('ossredact.dev.attacker.example')).toBe(false)
  })

  it('keeps the full UI for loopback, dev, and self-hosted origins', () => {
    expect(isHostedDemo('127.0.0.1')).toBe(false)
    expect(isHostedDemo('localhost')).toBe(false)
    expect(isHostedDemo('tauri.localhost')).toBe(false)
    expect(isHostedDemo('console.tail1234.ts.net')).toBe(false)
    expect(isHostedDemo('my-home-server')).toBe(false)
  })

  it('documents the loopback gate default, never a web origin', () => {
    expect(HOSTED_DOC_BASE).toBe('http://127.0.0.1:8011')
  })
})
