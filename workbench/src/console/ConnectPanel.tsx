import { useState } from 'react'
import {
  cleartextRisk,
  connectBase,
  connectGate,
  getControlToken,
  getDaemonOverride,
  mixedContentRisk,
  probe,
  setControlToken,
  setDaemonOverride,
  type ConnectOutcome,
  type ProbeResult,
} from '../lib/daemon'

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
      where: 'Run these in the terminal before you start Claude Code. Every request is redacted on the way out and rehydrated on the way back. The [1m] model suffix keeps the context bar sized to the model’s true 1M window; without it, Claude Code treats the proxy as non-first-party and caps the bar at 200k. Append it to any native-1M model (fable, opus, sonnet). On a direct connection Claude Code strips the suffix itself, so it is safe to keep permanently.',
      lang: 'bash',
      code: `export ANTHROPIC_BASE_URL=${b}\nclaude --model 'claude-fable-5[1m]'`,
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
 * Where THIS console connects to the gate. Lets the operator point it at a gate on ANOTHER machine
 * (off-device, e.g. a tailnet host) without rebuilding: enter the address (+ a control token if the
 * remote gate requires one), Test, and Connect. Persisted via daemon.ts (localStorage). Calls onChange
 * after a successful connect/reset so the parent re-renders the address + agent snippets.
 */
function GateConnection({ onChange }: { onChange: () => void }) {
  const [addr, setAddr] = useState(() => getDaemonOverride() || connectBase())
  const [token, setToken] = useState(() => getControlToken())
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState<ProbeResult | null>(null)
  const [outcome, setOutcome] = useState<ConnectOutcome | null>(null)
  const isOverride = !!getDaemonOverride()
  // A secure console (hosted https, or the Tauri webview) cannot reach a plain http:// remote gate -- the
  // browser blocks it as mixed content with an opaque failure. Warn while the operator is still typing.
  const mcRisk = mixedContentRisk(addr, typeof window !== 'undefined' ? window.location?.protocol ?? '' : '')
  // Even when not blocked (a plain-http console -> remote http gate works), a non-loopback http gate sends
  // traffic + the live PII proof feed in cleartext over the network. Warn unless mixed-content already covers it.
  const ctRisk = !mcRisk && cleartextRisk(addr)

  const test = async () => {
    setTesting(true)
    setResult(null)
    setOutcome(null)
    try {
      const r = await probe(addr.trim())
      setResult(r)
    } finally {
      setTesting(false)
    }
  }

  const connect = async () => {
    setTesting(true)
    setResult(null)
    setOutcome(null)
    try {
      // End-to-end: persist (inside connectGate) ONLY after the control token is actually authorized, never
      // on a bare /healthz probe -- otherwise a wrong/empty token reads green then silently 403s every /api/*.
      const o = await connectGate(addr.trim(), token.trim())
      setOutcome(o)
      if (o.ok) onChange()
    } finally {
      setTesting(false)
    }
  }

  const reset = () => {
    setDaemonOverride('')
    setControlToken('')
    setAddr(connectBase())
    setToken('')
    setResult(null)
    setOutcome(null)
    onChange()
  }

  return (
    <details className="mb-5 rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-[#191919]">
      <summary className="cursor-pointer select-none px-3.5 py-2.5 text-sm font-semibold text-gray-900 dark:text-neutral-100">
        Gate connection
        <span className="ml-2 font-normal text-xs text-gray-400 dark:text-neutral-500">
          {isOverride ? 'custom address' : 'this machine'}
        </span>
      </summary>
      <div className="space-y-3 border-t border-gray-100 dark:border-white/10 p-3.5">
        <p className="text-xs leading-relaxed text-gray-500 dark:text-neutral-400">
          Connect to a gate on <strong className="font-medium">another machine</strong> (e.g. a home-server or
          tailnet host). Point this at its address; if that gate sets a control token, paste the same value here.
          A gate on this machine needs no token.
        </p>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-gray-600 dark:text-neutral-300">Gate address</span>
          <input
            type="text"
            value={addr}
            onChange={(e) => setAddr(e.target.value)}
            placeholder="http://gate-host:8011"
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            className="w-full rounded-md border border-gray-300 dark:border-white/10 bg-white dark:bg-black/30 px-2.5 py-1.5 font-mono text-xs text-gray-800 dark:text-neutral-200 focus:outline-none focus:ring-2 focus:ring-teal-500"
          />
        </label>
        {mcRisk && (
          <p
            className="rounded-md border border-amber-300 dark:border-amber-400/30 bg-amber-50 dark:bg-amber-400/10 px-2.5 py-2 text-xs leading-relaxed text-amber-800 dark:text-amber-200"
            role="alert"
          >
            This console runs in a secure context, so your browser will <strong className="font-semibold">block</strong> a
            plain <code className="font-mono">http://</code> gate (mixed content) and the connection fails silently. Use an{' '}
            <code className="font-mono">https://</code> address -- the simplest path is <code className="font-mono">tailscale serve</code>{' '}
            (MagicDNS cert), which gives <code className="font-mono">https://&lt;host&gt;.&lt;tailnet&gt;.ts.net</code>. A gate
            on this machine (<code className="font-mono">http://127.0.0.1:8011</code>) is exempt.
          </p>
        )}
        {ctRisk && (
          <p
            className="rounded-md border border-amber-300 dark:border-amber-400/30 bg-amber-50 dark:bg-amber-400/10 px-2.5 py-2 text-xs leading-relaxed text-amber-800 dark:text-amber-200"
            role="alert"
          >
            This is a plain <code className="font-mono">http://</code> gate on another host, so your requests and
            the live PII proof feed travel in <strong className="font-semibold">cleartext</strong> over the network.
            Use it only on a trusted, encrypted network (a tailnet) -- prefer an <code className="font-mono">https://</code> address.
          </p>
        )}
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-gray-600 dark:text-neutral-300">
            Control token <span className="font-normal text-gray-400 dark:text-neutral-500">(only for an off-device gate)</span>
          </span>
          <input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="leave empty for a gate on this machine"
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            className="w-full rounded-md border border-gray-300 dark:border-white/10 bg-white dark:bg-black/30 px-2.5 py-1.5 font-mono text-xs text-gray-800 dark:text-neutral-200 focus:outline-none focus:ring-2 focus:ring-teal-500"
          />
        </label>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={test}
            disabled={testing || !addr.trim()}
            className="rounded-md border border-gray-300 dark:border-white/10 px-2.5 py-1 text-xs font-medium text-gray-700 dark:text-neutral-200 hover:bg-gray-50 dark:hover:bg-white/5 disabled:opacity-40 focus:outline-none focus:ring-2 focus:ring-teal-500"
          >
            {testing ? 'Testing…' : 'Test'}
          </button>
          <button
            type="button"
            onClick={connect}
            disabled={testing || !addr.trim()}
            className="rounded-md bg-teal-600 px-2.5 py-1 text-xs font-semibold text-white hover:bg-teal-500 disabled:opacity-40 focus:outline-none focus:ring-2 focus:ring-teal-500"
          >
            Connect
          </button>
          {isOverride && (
            <button
              type="button"
              onClick={reset}
              className="rounded-md border border-gray-300 dark:border-white/10 px-2.5 py-1 text-xs font-medium text-gray-500 dark:text-neutral-400 hover:bg-gray-50 dark:hover:bg-white/5 focus:outline-none focus:ring-2 focus:ring-teal-500"
            >
              Use this machine
            </button>
          )}
        </div>
        {outcome ? (
          <p
            className={`text-xs leading-relaxed ${
              outcome.ok ? 'text-teal-700 dark:text-teal-300' : 'text-rose-600 dark:text-rose-400'
            }`}
            role="status"
          >
            {outcome.ok ? (
              <>Connected -- control access verified{outcome.result.version ? ` (gate v${outcome.result.version})` : ''}.</>
            ) : outcome.reason === 'unauthorized' ? (
              <>Token rejected (HTTP {outcome.status ?? 403}): the gate is reachable but this control token is wrong or missing. Not saved.</>
            ) : outcome.reason === 'no-remote-control' ? (
              <>This gate has no control token configured, so it can only be managed from its own machine. Set <code className="font-mono">GATEWAY_CONTROL_TOKEN</code> on it to connect from here. Not saved.</>
            ) : outcome.reason === 'not-a-gate' ? (
              <>Reached an endpoint but it is not an OSSRedact gate (HTTP {outcome.status}). Not saved.</>
            ) : outcome.reason === 'unreachable' ? (
              <>Unreachable{outcome.result.error ? ` -- ${outcome.result.error}` : ''}. Check the address and that the gate is running. Not saved.</>
            ) : (
              <>Could not verify control access{outcome.status ? ` (HTTP ${outcome.status})` : ''}. Not saved.</>
            )}
          </p>
        ) : result ? (
          <p
            className={`text-xs leading-relaxed ${
              result.ok ? 'text-teal-700 dark:text-teal-300' : 'text-rose-600 dark:text-rose-400'
            }`}
            role="status"
          >
            {result.ok ? (
              <>
                Reachable -- OSSRedact gate{result.version ? ` v${result.version}` : ''}.{' '}
                {result.remoteControl
                  ? 'Accepts remote control (token required).'
                  : 'Loopback-only control -- set GATEWAY_CONTROL_TOKEN on it to manage remotely.'}
              </>
            ) : result.status ? (
              <>Reached an endpoint but it is not an OSSRedact gate (HTTP {result.status}).</>
            ) : (
              <>Unreachable{result.error ? ` -- ${result.error}` : ''}. Check the address and that the gate is running.</>
            )}
          </p>
        ) : null}
      </div>
    </details>
  )
}

/**
 * The "Connect" tab: the single instruction a new user needs -- how to point their coding agent at the
 * running firewall. Shows the live daemon address (so it is correct whether served same-origin, by the
 * Tauri shell, a hosted deploy, or an operator-set off-device gate) and copy-paste blocks for Claude Code,
 * Codex, and generic SDK clients.
 */
export default function ConnectPanel() {
  // Bumped after a successful connect/reset so the address box + agent snippets recompute from the new base.
  const [, bump] = useState(0)
  const base = connectBase()
  const snippets = connectSnippets(base)

  return (
    <div className="max-w-2xl">
      <GateConnection onChange={() => bump((n) => n + 1)} />
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
