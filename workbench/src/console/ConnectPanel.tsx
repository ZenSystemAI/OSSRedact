import { useState } from 'react'
import { connectBase } from '../lib/daemon'

// =============================================================================
// Pure helper (unit-tested in ConnectPanel.test.ts)
// =============================================================================

export interface ConnectSnippet {
  id: string
  /** Tool name shown as the card title. */
  tool: string
  /** One line on where this goes / what it does. */
  where: string
  /** The copy-paste block. */
  code: string
  /** Language hint for the <pre> (purely cosmetic). */
  lang: string
}

/**
 * Build the exact copy-paste setup blocks for pointing a coding agent at the local firewall, parameterized
 * by the daemon's loopback base URL (so the shown address always matches where THIS console's daemon lives).
 * Pure + exported so the address-substitution is unit-tested without rendering.
 */
export function connectSnippets(base: string): ConnectSnippet[] {
  const b = base.replace(/\/$/, '')
  return [
    {
      id: 'claude-code',
      tool: 'Claude Code',
      where: 'Run these in the terminal before you start Claude Code. Every request is redacted on the way out and rehydrated on the way back.',
      lang: 'bash',
      code: `export ANTHROPIC_BASE_URL=${b}\nclaude`,
    },
    {
      id: 'codex',
      tool: 'OpenAI Codex',
      where: 'Add to your user-level ~/.codex/config.toml (not the project file). Codex supplies its normal OpenAI auth; OSSRedact forwards it unchanged.',
      lang: 'toml',
      code: [
        'model_provider = "ossredact_chatgpt_plan"',
        '',
        '[model_providers.ossredact_chatgpt_plan]',
        'name = "OSSRedact bridge"',
        `base_url = "${b}/v1"`,
        'wire_api = "responses"',
        'requires_openai_auth = true',
      ].join('\n'),
    },
    {
      id: 'anthropic-sdk',
      tool: 'Anthropic SDK / other clients',
      where: 'Any Anthropic-compatible client: point its base URL at the firewall. OpenAI-compatible clients use the same address with a /v1 suffix.',
      lang: 'bash',
      code: `# Anthropic-style\nANTHROPIC_BASE_URL=${b}\n# OpenAI-style\nOPENAI_BASE_URL=${b}/v1`,
    },
  ]
}

// =============================================================================
// Component
// =============================================================================

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard blocked (rare on loopback) -- the user can select-and-copy manually */
    }
  }
  return (
    <button
      type="button"
      onClick={copy}
      className="flex-none rounded-md border border-gray-300 dark:border-white/10 px-2 py-1 text-xs font-medium text-gray-600 dark:text-neutral-300 hover:bg-gray-50 dark:hover:bg-white/5 focus:outline-none focus:ring-2 focus:ring-teal-500"
      aria-label={copied ? 'Copied' : 'Copy to clipboard'}
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

/**
 * The "Connect" tab: the single instruction a new user needs -- how to point their coding agent at the
 * running firewall. Shows the live daemon address (so it is correct whether served same-origin, by the
 * Tauri shell, or a hosted deploy) and copy-paste blocks for Claude Code, Codex, and generic SDK clients.
 */
export default function ConnectPanel() {
  const base = connectBase()
  const snippets = connectSnippets(base)

  return (
    <div className="max-w-2xl">
      <div className="mb-4">
        <h2 className="text-sm font-semibold text-gray-900 dark:text-neutral-100">Connect your coding agent</h2>
        <p className="mt-1 text-xs leading-relaxed text-gray-500 dark:text-neutral-400">
          Point your agent at the firewall and it redacts every request before it leaves your machine, then
          puts the real values back in the reply. Nothing else to configure.
        </p>
      </div>

      <div className="mb-5 flex flex-wrap items-center gap-2 rounded-lg border border-teal-200 dark:border-teal-400/20 bg-teal-50 dark:bg-teal-400/10 p-3">
        <span className="text-xs font-medium text-teal-800 dark:text-teal-200">Firewall address</span>
        <code className="rounded bg-white/70 dark:bg-black/30 px-2 py-0.5 font-mono text-xs text-teal-900 dark:text-teal-100">
          {base}
        </code>
        <span className="flex-1" />
        <CopyButton text={base} />
      </div>

      <div className="space-y-4">
        {snippets.map((s) => (
          <div key={s.id} className="rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-[#191919] p-3.5">
            <div className="mb-1 flex items-center gap-2">
              <h3 className="text-sm font-semibold text-gray-900 dark:text-neutral-100">{s.tool}</h3>
              <span className="flex-1" />
              <span className="rounded bg-gray-100 dark:bg-white/10 px-1.5 py-0.5 font-mono text-[11px] text-gray-500 dark:text-neutral-400">
                {s.lang}
              </span>
            </div>
            <p className="mb-2.5 text-xs leading-relaxed text-gray-500 dark:text-neutral-400">{s.where}</p>
            <div className="flex items-start gap-2">
              <pre className="min-w-0 flex-1 overflow-x-auto rounded-md bg-gray-50 dark:bg-black/40 p-2.5 font-mono text-xs leading-relaxed text-gray-800 dark:text-neutral-200">
                {s.code}
              </pre>
              <CopyButton text={s.code} />
            </div>
          </div>
        ))}
      </div>

      <p className="mt-5 text-xs leading-relaxed text-gray-400 dark:text-neutral-500">
        Watch it work in the <strong className="font-medium text-gray-500 dark:text-neutral-400">Live activity</strong> tab:
        send one message from your agent and the redacted entities appear in real time. The deterministic
        floor (secrets, payment cards, government IDs) is always on, in every mode.
      </p>
    </div>
  )
}
