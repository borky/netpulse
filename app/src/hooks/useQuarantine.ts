import { useEffect, useState } from 'react'
import type { QuarantineEntry } from '@/data/types'
import { fetchJson } from '@/lib/utils'

/** How often the device list re-reads the quarantine (routers report it with
 *  each full push, every 30 s by default). */
const REFRESH_MS = 30_000

/**
 * The device quarantine the routers' panels (NetGrip) report, by lowercase
 * MAC. The server answers only over HTTPS (the trusted list is what someone
 * copying a MAC wants), so over plain HTTP, in the demo, or with no panel
 * reporting, this is an empty map and the list shows nothing.
 */
export function useQuarantine(enabled: boolean): Map<string, QuarantineEntry> {
  const [byMac, setByMac] = useState<Map<string, QuarantineEntry>>(() => new Map())
  useEffect(() => {
    if (!enabled) {
      setByMac(new Map())
      return
    }
    let disposed = false
    const load = async () => {
      const r = await fetchJson<{ secure: boolean; devices: QuarantineEntry[] }>('/api/quarantine')
      if (disposed || !r.ok) return
      setByMac(new Map((r.data.devices ?? []).map((d) => [d.mac.toLowerCase(), d])))
    }
    void load()
    const id = window.setInterval(() => void load(), REFRESH_MS)
    return () => {
      disposed = true
      window.clearInterval(id)
    }
  }, [enabled])
  return byMac
}

/** The entry for a device: its own MAC first, then its linked addresses. */
export function quarantineFor(
  byMac: Map<string, QuarantineEntry>,
  mac: string,
  aliases?: string[],
): QuarantineEntry | undefined {
  for (const m of [mac, ...(aliases ?? [])]) {
    const e = byMac.get(m.toLowerCase())
    if (e) return e
  }
  return undefined
}
