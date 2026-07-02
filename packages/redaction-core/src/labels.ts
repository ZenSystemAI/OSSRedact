// Display metadata for entity labels. Keys match the appliance's span labels (privacy_gate.py +
// the NPU/GPU model's id2label, the 20-label v11 scheme in training/labels_v20.json). Unknown labels
// fall back to a neutral teal so any neural label we haven't explicitly mapped still renders cleanly.

export type LabelMeta = { en: string; fr: string; color: string }
export type Tier = 'catastrophic' | 'operational'

export const LABEL_REGISTRY: Record<string, LabelMeta> = {
  // --- catastrophic tier (irreversible-harm PII; redact-by-default, recall-first) ---
  government_id: { en: 'Gov ID / SIN', fr: 'NAS / pièce', color: '#ef4444' },
  payment_card: { en: 'Card number', fr: 'No de carte', color: '#f59e0b' },
  card_cvv: { en: 'Card CVV', fr: 'CVV', color: '#fb923c' },
  card_expiry: { en: 'Card expiry', fr: 'Expiration carte', color: '#fdba74' },
  iban: { en: 'IBAN', fr: 'IBAN', color: '#14b8a6' },
  account_number: { en: 'Account number', fr: 'No de compte', color: '#a78bfa' },
  sensitive_account_id: { en: 'Account / file ID', fr: 'Compte / no dossier', color: '#c084fc' },
  // 2026-07-02 fat-floor diet twins: 'uuid' = deterministic UUID-shape detection DEMOTED from the floor
  // (session/request ids are load-bearing in coding traffic; the WIRE passes them in coding mode), and
  // 'sensitive_ref' = a MODEL-claimed account/gov identity span stripped of floor privileges (deterministic
  // provenance owns the hard guarantee). Both stay catastrophic-tier for DISPLAY: in the Workbench,
  // redact-by-default with the per-label toggle is the right default for document review.
  uuid: { en: 'Session / request ID', fr: 'ID de session / requête', color: '#d8b4fe' },
  sensitive_ref: { en: 'Sensitive reference', fr: 'Référence sensible', color: '#c4b5fd' },
  tax_id: { en: 'Tax ID', fr: 'No fiscal', color: '#f472b6' },
  secret: { en: 'Secret / key', fr: 'Secret / clé', color: '#fb7185' },
  password: { en: 'Password', fr: 'Mot de passe', color: '#f43f5e' },
  email: { en: 'Email', fr: 'Courriel', color: '#4ecdb8' },
  person: { en: 'Name', fr: 'Nom', color: '#4ade80' },
  date_of_birth: { en: 'Date of birth', fr: 'Date de naissance', color: '#94a3b8' },
  // --- operational tier (useful-to-redact but lower-harm; precision-first) ---
  phone_number: { en: 'Phone', fr: 'Téléphone', color: '#6fd9c7' },
  address: { en: 'Address', fr: 'Adresse', color: '#fbbf24' },
  postal_code: { en: 'Postal code', fr: 'Code postal', color: '#60a5fa' },
  ip_address: { en: 'IP address', fr: 'Adresse IP', color: '#38bdf8' },
  file_path: { en: 'File path', fr: 'Chemin de fichier', color: '#64748b' },
  username: { en: 'Username', fr: "Nom d'utilisateur", color: '#818cf8' },
  organization: { en: 'Organization', fr: 'Organisation', color: '#a3e635' },
  // --- aliases / manual ---
  name: { en: 'Name', fr: 'Nom', color: '#4ade80' }, // legacy alias of person
  sensitive_date: { en: 'Date', fr: 'Date', color: '#94a3b8' }, // legacy alias of date_of_birth
  manual: { en: 'Manual', fr: 'Manuel', color: '#4ecdb8' },
}

const FALLBACK: LabelMeta = { en: 'Sensitive', fr: 'Sensible', color: '#4ecdb8' }

// The catastrophic tier (design spec 3.8): irreversible-harm PII the gate must never leak. Manual
// redactions and unknown labels are treated as catastrophic (redact-by-default = the safe error).
const CATASTROPHIC = new Set<string>([
  'government_id', 'payment_card', 'card_cvv', 'card_expiry', 'iban', 'account_number',
  'sensitive_account_id', 'tax_id', 'secret', 'password', 'email', 'person', 'date_of_birth',
  'name', 'sensitive_date', 'manual',
  // Display tier only -- NOT floor members. See the registry comment on the 2026-07-02 demotion.
  'uuid', 'sensitive_ref',
])

// The HARD FLOOR: credential + money/government/identity labels that are NEVER allowlist-exempt and are
// force-redacted in every mode. Mirrors the Python gate's privacy_gate.FLOOR_LABELS 1:1 (detector-twin
// parity). NOTE this is a STRICT SUBSET of CATASTROPHIC -- soft catastrophic labels (person, email,
// address) are redact-by-default but CAN be allowlisted/turned off; the floor labels here cannot.
export const FLOOR_LABELS: ReadonlySet<string> = new Set<string>([
  'secret', 'password', 'api_key', 'access_token',
  'payment_card', 'card_cvv', 'card_expiry',
  'sensitive_account_id', 'bank_account', 'account_number', 'iban', 'routing_number',
  'government_id', 'tax_id', 'date_of_birth',
])

export function labelMeta(label: string): LabelMeta {
  return LABEL_REGISTRY[label] ?? { ...FALLBACK, en: prettify(label), fr: prettify(label) }
}

export function labelTier(label: string): Tier {
  // default to catastrophic for unknown labels: over-redaction is the safe error for a privacy gate
  return CATASTROPHIC.has(label) ? 'catastrophic' : 'operational'
}

function prettify(label: string): string {
  return label.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

// Manual-redaction label choices offered in the UI (value -> display).
export const MANUAL_LABELS = [
  'manual',
  'person',
  'address',
  'email',
  'phone_number',
  'account_number',
  'sensitive_account_id',
  'payment_card',
  'government_id',
  'tax_id',
  'organization',
  'date_of_birth',
] as const
