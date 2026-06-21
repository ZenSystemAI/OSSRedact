// Canonical placeholder contract shared with appliance/entity_map.py.
// Any change here must update the Python side and both guard tests:
// <LABEL_NNN>, label [A-Z0-9_]+, 3 or more decimal digits.
export const PLACEHOLDER_CONTRACT_PATTERN = '^<([A-Z0-9_]+)_\\d{3,}>$'
export const PLACEHOLDER_CONTRACT_RE = /^<([A-Z0-9_]+)_\d{3,}>$/

