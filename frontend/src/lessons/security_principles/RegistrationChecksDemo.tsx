import { useState } from 'react'
import { request } from '../../api'

type Result = {
  examples: {
    label: string
    queue: string
    decision: { code: string; message: string }
  }[]
  rejected_code: string
  incident_count: number
}

export function RegistrationChecksDemo({ token }: { token: string }) {
  const [result, setResult] = useState<Result>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function compare() {
    setBusy(true)
    setResult(undefined)
    setError('')
    try {
      setResult(await request<Result>('/api/registration-checks-demo', { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось проверить регистрацию.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Проверки перед вызовом">
      <h2>Проверки перед вызовом</h2>
      <p>Сравните проверку черновика P2 до подтверждения, после подтверждения и после изменения очереди.</p>
      <button className="outline" disabled={busy} onClick={() => void compare()}>
        {busy ? 'Выполняем проверки…' : 'Сравнить проверки регистрации'}
      </button>
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {result && (
          <>
            <div className="outcome-grid">
              {result.examples.map(item => (
                <article className="outcome-card" key={item.label}>
                  <h3>{item.label}</h3>
                  <p>Очередь · {item.queue}</p>
                  <p>{item.decision.message}</p>
                  <small>Решение · <code>{item.decision.code}</code></small>
                </article>
              ))}
            </div>
            <p>Попытка регистрации в очереди «Платежи» · <code>{result.rejected_code}</code></p>
            <p><strong>Карточек в трекере: {result.incident_count}</strong></p>
          </>
        )}
      </div>
    </section>
  )
}
