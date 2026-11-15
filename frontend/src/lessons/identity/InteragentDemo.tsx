import { useState } from 'react'
import { request } from '../../api'

type Check = { status: number; code: string | null }
type Result = {
  read: { source: string; summary: string }
  incident: Check
  unverified_transport: Check
}

export function InteragentDemo({ token, enabled }: { token: string; enabled: boolean }) {
  const [result, setResult] = useState<Result>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function run() {
    setBusy(true)
    setError('')
    setResult(undefined)
    try {
      setResult(await request<Result>('/api/interagent-demo', { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось проверить доступ агента.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Межагентная аутентификация">
      <h2>Межагентная аутентификация</h2>
      {enabled ? (
        <>
          <p>Исполнитель сверяет сертификат агента регламентов с OAuth-токеном и проверяет права отдельно для каждой операции.</p>
          <button className="outline" disabled={busy} onClick={() => void run()}>
            {busy ? 'Проверяем доступ…' : 'Проверить доступ агента регламентов'}
          </button>
        </>
      ) : (
        <p>Для демонстрации запустите <code>scripts/start-interagent.ps1</code>.</p>
      )}
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {result && (
          <>
            <p><strong>{result.read.source}</strong> · HTTP 200</p>
            <p>{result.read.summary}</p>
            <div className="outcome-grid">
              <article className="outcome-card">
                <h3>Создание инцидента</h3>
                <p>HTTP {result.incident.status} · <code>{result.incident.code}</code></p>
              </article>
              <article className="outcome-card">
                <h3>Чтение с токеном без сертификата</h3>
                <p>HTTP {result.unverified_transport.status} · <code>{result.unverified_transport.code}</code></p>
              </article>
            </div>
          </>
        )}
      </div>
    </section>
  )
}
