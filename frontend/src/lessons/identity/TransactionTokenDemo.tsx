import { useState } from 'react'
import { request } from '../../api'

type Comparison = {
  changed_code: string
  incidents_after_change: number
  incident_id: string
  repeated_incident_id: string
  incident_count: number
}

export function TransactionTokenDemo({ token }: { token: string }) {
  const [result, setResult] = useState<Comparison>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function compare() {
    setBusy(true)
    setError('')
    setResult(undefined)
    try {
      setResult(await request<Comparison>('/api/transaction-token-demo', { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось проверить токен операции.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Токен операции">
      <h2>Токен операции</h2>
      <p>Дежурный подтверждает черновик P2. Исполнитель сравнивает параметры при записи и возвращает сохранённый результат при повторе.</p>
      <button className="outline" disabled={busy} onClick={() => void compare()}>
        {busy ? 'Проверяем согласование…' : 'Проверить изменение и повтор'}
      </button>
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {result && (
          <div className="outcome-grid">
            <article className="outcome-card">
              <h3>Приоритет изменился на P1</h3>
              <p>Требуется новое подтверждение · <code>{result.changed_code}</code></p>
              <p>Карточек в трекере · {result.incidents_after_change}</p>
            </article>
            <article className="outcome-card">
              <h3>Повтор с тем же ключом</h3>
              <p>После нового подтверждения · <strong>{result.incident_id}</strong></p>
              <p>После повтора · <strong>{result.repeated_incident_id}</strong></p>
              <p>Карточек в трекере · {result.incident_count}</p>
            </article>
          </div>
        )}
      </div>
    </section>
  )
}
