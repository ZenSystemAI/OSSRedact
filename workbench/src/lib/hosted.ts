// The PUBLIC hosted demo (the product site's /app) must never act as a gate control surface.
// Traffic never transits the site (a browser console talks to a gate directly), but a gate that
// allowlisted the site origin would hand its control plane -- the live PII proof feed, dictionary,
// and firewall toggle -- to whatever script the site's next deploy ships. One compromised deploy
// would expose every opted-in gate at once. So on the hosted origin the console renders a read-only
// funnel: agent snippets + pointers to the desktop app and the gate-served console. Loopback-served
// consoles (the gate's own /console, dev), the Tauri shell, and operator-self-hosted deploys keep
// the full gate-connection UI: those origins are the operator's own trust domain.
const HOSTED_DEMO_HOST_RE = /(^|\.)ossredact\.dev$|(^|\.)vercel\.app$/i

/** True when this build is running on the public product site (or its Vercel previews). */
export function isHostedDemo(hostname?: string): boolean {
  const h = hostname ?? (typeof window !== 'undefined' ? (window.location?.hostname ?? '') : '')
  return HOSTED_DEMO_HOST_RE.test(h)
}

/**
 * The gate address the hosted demo DOCUMENTS (the loopback default on the machine that runs the
 * gate). Never the page origin: connectBase() falls back to window.location.origin, which on the
 * hosted site is the website itself -- an agent pointed there would ship its traffic to the web
 * host instead of a firewall.
 */
export const HOSTED_DOC_BASE = 'http://127.0.0.1:8011'
