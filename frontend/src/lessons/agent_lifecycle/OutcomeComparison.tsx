import { useState } from 'react'
import { Lifecycle, phaseLabels } from '../../workbench/Lifecycle'
import type { LifecycleEvent, Phase } from '../../workbench/Lifecycle'
import { request } from '../../api'

type Outcome = {
  case: string
  title: string
  checkpoints: {
    title: string
    operator: string
    status: Phase
    incident_count: number
    incident_id: string | null
  }[]
  trace: { lifecycle: { events: LifecycleEvent[] } }
}

export function OutcomeComparison({ token }: { token: string }) {
  const [results, setResults] = useState<Outcome[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function compare() {
    setBusy(true)
    setError('')
    setResults([])
    try {
      setResults(await request<Outcome[]>('/api/outcome-comparison', { method: 'POST' }, token))
    } catch {
      setError('Не удалось сравнить исходы. Проверьте, что сервер работает, и повторите прогон.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Исходы обработки обращения">
      <h2>Что происходит при сбое</h2>
      <p>Сравните штатный маршрут, отказ политики, недоступность модели и потерю ответа трекера.</p>
      <button className="outline" onClick={() => void compare()} disabled={busy}>
        {busy ? 'Выполняются прогоны…' : 'Сравнить исходы'}
      </button>
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {results.length > 0 && (
          <div className="outcome-grid">
            {results.map(result => (
              <article key={result.case} className="outcome-card">
                <h3>{result.title}</h3>
                <ol>
                  {result.checkpoints.map(check => (
                    <li key={check.title}>
                      <strong>{check.title}</strong>
                      <p className="secondary">{check.operator}</p>
                      <p>
                        {phaseLabels[check.status]} · Карточек в трекере: {check.incident_count}
                        {check.incident_id && ` · ${check.incident_id}`}
                      </p>
                    </li>
                  ))}
                </ol>
                <details>
                  <summary>История действий</summary>
                  <Lifecycle events={result.trace.lifecycle.events} />
                </details>
              </article>
            ))}
          </div>
        )}
      </div>
    </section>
  )
}
