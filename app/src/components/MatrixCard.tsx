import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Send, Loader2, Check, Eye, EyeOff, MessagesSquare } from 'lucide-react'
import { Switch } from '@/components/ui/switch'
import { InfoTip } from '@/components/InfoTip'

type MatrixState = 'loading' | 'idle' | 'saving' | 'testing' | 'saved' | 'error'

interface MatrixConfig {
  server: string
  roomId: string
  token: string
  urgentOnly: boolean
}

// MatrixCard: the Matrix channel. The server checks the token and the room
// membership before it saves, and stores all three values encrypted; the
// token is write-only and is sent only when typed.
export default function MatrixCard({ onSaved, bare = true }: { onSaved: () => void; bare?: boolean }) {
  const { t } = useTranslation()
  const [state, setState] = useState<MatrixState>('loading')
  const [cfg, setCfg] = useState<MatrixConfig>({ server: '', roomId: '', token: '', urgentOnly: true })
  const [tokenSet, setTokenSet] = useState(false)
  const [unreadable, setUnreadable] = useState(false)
  const [secretsUnavailable, setSecretsUnavailable] = useState(false)
  const [showToken, setShowToken] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let alive = true
    void fetch('/api/settings/matrix')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!alive || !d) return
        setCfg({ server: d.server || '', roomId: d.roomId || '', token: '', urgentOnly: d.urgentOnly !== false })
        setTokenSet(!!d.tokenSet)
        setUnreadable(!!d.unreadable)
        setSecretsUnavailable(!!d.secretsUnavailable)
        setState('idle')
      })
      .catch(() => {
        if (alive) setState('idle')
      })
    return () => {
      alive = false
    }
  }, [])

  const save = useCallback(async () => {
    if (!cfg.server.trim() || !cfg.roomId.trim() || (!tokenSet && !cfg.token.trim())) {
      setError(t('settings.matrix.incomplete'))
      setState('error')
      return
    }
    setState('saving')
    setError('')
    try {
      const body: Record<string, unknown> = {
        server: cfg.server.trim(),
        roomId: cfg.roomId.trim(),
        // The enable switch is the row outside this dialog; configuring
        // here leaves the channel ready and the gate decides per event.
        enabled: true,
        urgentOnly: cfg.urgentOnly,
      }
      if (cfg.token.trim()) body.token = cfg.token.trim()
      const res = await fetch('/api/settings/matrix', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = (await res.json().catch(() => null)) as { message?: string; error?: { message?: string } } | null
      if (!res.ok) {
        setError(data?.message ?? data?.error?.message ?? 'Save failed')
        setState('error')
        return
      }
      if (cfg.token.trim()) setTokenSet(true)
      setUnreadable(false)
      setCfg((c) => ({ ...c, token: '' }))
      setState('saved')
      onSaved()
      setTimeout(() => setState('idle'), 1500)
    } catch {
      setError('Network error')
      setState('error')
    }
  }, [cfg, tokenSet, onSaved, t])

  const test = useCallback(async () => {
    setState('testing')
    setError('')
    try {
      const res = await fetch('/api/settings/matrix/test', { method: 'POST' })
      if (!res.ok) {
        const data = (await res.json().catch(() => null)) as { message?: string; error?: { message?: string } } | null
        setError(data?.message ?? data?.error?.message ?? 'Test failed')
        setState('error')
        return
      }
      setState('saved')
      setTimeout(() => setState('idle'), 1500)
    } catch {
      setError('Network error')
      setState('error')
    }
  }, [])

  if (state === 'loading') {
    return <p className="text-caption text-text-muted">{t('common.loading')}</p>
  }

  const busy = state === 'saving' || state === 'testing'
  const inputCls =
    'w-full rounded-md border border-border bg-elevated px-2.5 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none'
  const labelCls = 'mb-1 flex items-center gap-1 text-[11px] font-medium uppercase tracking-wider text-text-muted'

  const header = (
    <>
      <div className="mb-3 flex items-center gap-2">
        <MessagesSquare className="h-4 w-4 text-accent" strokeWidth={2} />
        <h3 className="text-sm font-semibold text-text-primary">{t('settings.matrix.title')}</h3>
      </div>
      <p className="mb-3 text-xs text-text-secondary">{t('settings.matrix.description')}</p>
    </>
  )

  const form = (
    <>
      {secretsUnavailable ? (
        <p className="mb-3 rounded-md bg-danger/10 px-2.5 py-2 text-xs text-danger">{t('settings.matrix.secretsUnavailable')}</p>
      ) : (
        unreadable && <p className="mb-3 rounded-md bg-warn/10 px-2.5 py-2 text-xs text-warn">{t('settings.matrix.unreadable')}</p>
      )}

      <div className="flex items-center justify-between gap-4 py-1">
        <span className="flex items-center gap-1 text-sm font-medium text-text-primary">
          {t('settings.matrix.urgentOnly')}
          <InfoTip text={t('settings.matrix.urgentOnlyHint')} />
        </span>
        <Switch
          checked={cfg.urgentOnly}
          onCheckedChange={(v) => setCfg((c) => ({ ...c, urgentOnly: v }))}
          aria-label={t('settings.matrix.urgentOnly')}
        />
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <label className={labelCls}>{t('settings.matrix.server')}</label>
          <input
            type="url"
            value={cfg.server}
            onChange={(e) => setCfg((c) => ({ ...c, server: e.target.value }))}
            placeholder="https://matrix.example.org"
            autoComplete="off"
            className={inputCls}
          />
        </div>

        <div>
          <label className={labelCls}>
            {t('settings.matrix.roomId')}
            <InfoTip text={t('settings.matrix.roomIdHint')} />
          </label>
          <input
            type="text"
            value={cfg.roomId}
            onChange={(e) => setCfg((c) => ({ ...c, roomId: e.target.value }))}
            placeholder="!AbCdEfGhIjKlMnOp"
            autoComplete="off"
            className={inputCls}
          />
        </div>

        <div className="sm:col-span-2">
          <label className={labelCls}>
            {t('settings.matrix.token')}
            <InfoTip text={t('settings.matrix.tokenHint')} />
            {tokenSet ? <span className="ml-1.5 normal-case text-ok">{t('settings.matrix.tokenSet')}</span> : null}
          </label>
          <div className="flex items-center gap-1">
            <input
              type={showToken ? 'text' : 'password'}
              value={cfg.token}
              onChange={(e) => setCfg((c) => ({ ...c, token: e.target.value }))}
              placeholder={tokenSet ? t('settings.matrix.tokenKeep') : 'syt_…'}
              autoComplete="new-password"
              className={`flex-1 ${inputCls.replace('w-full ', '')}`}
            />
            <button
              type="button"
              onClick={() => setShowToken((v) => !v)}
              className="rounded-md border border-border p-1.5 text-text-muted hover:text-text-primary"
              title={showToken ? 'Hide' : 'Show'}
            >
              {showToken ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>
      </div>

      {error && <p className="mt-2 text-xs text-danger">{error}</p>}

      <div className="mt-3 flex items-center gap-2">
        <button
          type="button"
          onClick={() => void save()}
          disabled={busy || secretsUnavailable}
          className="inline-flex h-9 shrink-0 cursor-pointer items-center gap-1.5 rounded-xl bg-accent px-3 text-[13px] font-semibold text-canvas transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {state === 'saving' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" strokeWidth={2.5} />}
          {t('common.save')}
        </button>
        <button
          type="button"
          onClick={() => void test()}
          disabled={busy || !tokenSet}
          className="inline-flex h-9 shrink-0 cursor-pointer items-center gap-1.5 rounded-xl border border-border bg-elevated px-3 text-[13px] font-medium text-text-primary transition-colors hover:bg-hover disabled:cursor-not-allowed disabled:opacity-50"
        >
          {state === 'testing' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" strokeWidth={1.75} />}
          {t('settings.matrix.sendTest')}
        </button>
      </div>
    </>
  )

  if (bare) {
    return form
  }

  return (
    <div className="rounded-lg border border-border bg-surface p-4">
      {header}
      <div className="space-y-3">{form}</div>
    </div>
  )
}
