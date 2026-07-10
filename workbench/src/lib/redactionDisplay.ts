export function pinnedRedactionText(original: string): string {
  return original.replace(/[^\s]/g, '█')
}
