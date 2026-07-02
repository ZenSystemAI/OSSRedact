// Point-and-click firewall control from the desktop console: start/stop the local OSSRedact user services
// and toggle whether Claude Code routes through the firewall. These call native Tauri commands (see
// src-tauri/src/lib.rs) and ONLY work inside the desktop app -- in a plain browser they throw, so callers
// guard with isTauri() (the controls are hidden in the browser).

import { isTauri } from '../tauri-bootstrap'

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  // Lazy import so the browser bundle never hard-depends on the Tauri API at module load.
  const { invoke } = await import('@tauri-apps/api/core')
  return invoke<T>(cmd, args)
}

export type FirewallStatus = 'active' | 'inactive'

/** Start / stop / restart the two user services, or query status. Returns the resulting status. */
export async function firewallControl(
  action: 'start' | 'stop' | 'restart' | 'status',
): Promise<FirewallStatus> {
  if (!isTauri()) throw new Error('firewall control is only available in the desktop app')
  const s = await invoke<string>('firewall_control', { action })
  return s === 'active' ? 'active' : 'inactive'
}

/** Read / set whether Claude Code routes through the firewall (flips ANTHROPIC_BASE_URL in settings.json). */
export async function routingConfig(action: 'get' | 'enable' | 'disable'): Promise<boolean> {
  if (!isTauri()) throw new Error('routing control is only available in the desktop app')
  return invoke<boolean>('routing_config', { action })
}
