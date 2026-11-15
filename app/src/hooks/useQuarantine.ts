import { useEffect, useState } from 'react'
import type { QuarantineEntry } from '@/data/types'

/** How often the device list re-reads the quarantine (routers report it with
 *  each full push, every 30 s by default). */
const REFRESH_MS = 30_000

/**
 * The device quarantine the routers' panels (NetGrip) report, by lowercase
 * MAC. The server answers only admins and only over HTTPS (the trusted list
 * is what someone copying a MAC wants), so otherwise, in the demo, or with
 * no panel reporting, this is an empty map and the list shows nothing.
 */
export function useQuarantine(enabled: boolean): Map<string, QuarantineEntry> {
  const [byMac, setByMac] = useState<Map<string, QuarantineEntry>>(() => new Map())
  useEffect(() => {
    if (!enabled) {
      setByMac(new Map())
      return
    }
    let disposed = false
    let last = ''
    const load = async () => {
      let res: Response
      try {
        res = await fetch('/api/quarantine')
      } catch {
        return // network trouble: try again at the next tick
      }
      if (disposed) return
      // Not an admin (403), or a server without this endpoint: nothing
      // will come, so stop asking.
      if (res.status === 403 || res.status === 404) {
        window.clearInterval(id)
        return
      }
      if (!res.ok || !(res.headers.get('content-type') ?? '').includes('application/json')) return
      const data = (await res.json()) as { secure?: boolean; devices?: QuarantineEntry[] }
      if (disposed) return
      if (data.secure === false) window.clearInterval(id) // plain HTTP: the server never lists it
      // A new map only when something changed, so the device list is not
      // rebuilt every poll.
      const raw = JSON.stringify(data.devices ?? [])
      if (raw === last) return
      last = raw
      setByMac(new Map((data.devices ?? []).map((d) => [d.mac.toLowerCase(), d])))
    }
    const id = window.setInterval(() => void load(), REFRESH_MS)
    void load()
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
