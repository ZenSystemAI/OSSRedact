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
