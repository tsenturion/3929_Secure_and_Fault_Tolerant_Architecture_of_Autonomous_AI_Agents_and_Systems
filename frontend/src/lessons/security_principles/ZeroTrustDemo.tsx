import { useState } from 'react'
import { request } from '../../api'

type Comparison = {
  service: string
  operator: string
  action: string
  results: { resource: string; allowed: boolean; code: string; message: string; source: string | null }[]
}

export function ZeroTrustDemo({ token }: { token: string }) {
  const [comparison, setComparison] = useState<Comparison>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function run() {
    setBusy(true)
    setError('')
    setComparison(undefined)
    try {
      setComparison(await request<Comparison>('/api/zero-trust-demo', { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось проверить доступ.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Zero Trust">
      <h2>Zero Trust</h2>
      <p>Один сервис и одно действие. Исполнитель проверяет доступ к каждому ресурсу отдельно.</p>
      <button className="outline" disabled={busy} onClick={() => void run()}>
        {busy ? 'Проверяем доступ…' : 'Сравнить доступ к ресурсам'}
      </button>
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {comparison && (
          <>
            <p><code>{comparison.service}</code> · <code>{comparison.operator}</code> · <code>{comparison.action}</code></p>
            <div className="outcome-grid">
              {comparison.results.map(result => (
                <article className="outcome-card" key={result.resource}>
                  <h3>{result.resource}</h3>
                  <p><strong>{result.allowed ? 'Доступ разрешён' : 'Доступ запрещён'}</strong> · <code>{result.code}</code></p>
                  <p>{result.source ?? result.message}</p>
                </article>
              ))}
            </div>
          </>
        )}
      </div>
    </section>
  )
}
