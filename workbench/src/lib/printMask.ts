import { PLACEHOLDER_RE } from './formats'
import type { EntityMap } from './types'

const PRINT_MASK = '████████'

export function maskPlaceholdersForPrint(redacted: string, map: EntityMap): string {
  return redacted.replace(PLACEHOLDER_RE, (placeholder) =>
    Object.prototype.hasOwnProperty.call(map, placeholder) ? PRINT_MASK : placeholder,
  )
}
