// Fail-closed contract for a degraded in-browser deep scan.
//
// The browser redactor runs two tiers: the deterministic Tier-0 floor (structured / number-shaped PII +
// cue-anchored names -- always available, no model) and an OPTIONAL neural tier (the ~278 MB on-device model)
// that owns free-text PII. If the model fails to load (404 on a standalone serve, ERR_CACHE_WRITE_FAILURE, a
// WASM-less browser, a dropped download), detection silently degrades to Tier-0 only. Tier-0 has ZERO coverage
// of the labels below, so a degraded scan leaks them -- and a UI that still presents the output as "redacted"
// fails OPEN on the highest-risk PII category.
//
// This module is the SINGLE SOURCE OF TRUTH shared by every surface that runs the browser redactor (the
// workbench and the public web demo, kept in lockstep). Each UI imports the same label set + warning text and
// must (a) show the warning persistently -- never a dismissible toast -- while degraded, and (b) require an
// explicit acknowledgement before copy/download/print of degraded output. Do not fork this text or list per UI.

/**
 * Labels the deterministic Tier-0 floor does NOT reliably emit -- they are detected only by the neural tier,
 * so a degraded (Tier-0-only) scan can leak them. `person` is PARTIALLY covered (cue-anchored names via
 * cueNameSpans), but uncued free-text names are neural-only, so it belongs here for the user-facing warning.
 * Mirrors the documented tier split (README: account_number is the neural-only watch-item; person/org/address
 * are free-text PII the neural tier owns).
 */
export const NEURAL_ONLY_LABELS: ReadonlySet<string> = new Set<string>([
  'person',
  'organization',
  'address',
  'account_number',
])

/** True if a degraded scan could leak this label (i.e. Tier-0 alone does not reliably catch it). */
export function isNeuralOnlyLabel(label: string): boolean {
  return NEURAL_ONLY_LABELS.has(label)
}

/** The canonical, human-facing warning shown (persistently) whenever the deep scan degraded to Tier-0 only. */
export const DEEP_DEGRADED_WARNING =
  'Deep scan unavailable — only structured data (secrets, IDs, card and account numbers, emails, dates) was ' +
  'checked. Names, organizations, and addresses were NOT scanned and may remain in the output. Review before ' +
  'you export.'

/** Short label for a degraded state, for compact chips/badges. */
export const DEEP_DEGRADED_BADGE = 'Tier-0 only — names/orgs/addresses NOT scanned'

/** The confirmation a user must accept to export degraded output (fail-closed gate copy). */
export const DEEP_DEGRADED_EXPORT_CONFIRM =
  'The deep scan did not run, so names, organizations, and addresses may NOT be redacted. ' +
  'Export the Tier-0-only result anyway?'
