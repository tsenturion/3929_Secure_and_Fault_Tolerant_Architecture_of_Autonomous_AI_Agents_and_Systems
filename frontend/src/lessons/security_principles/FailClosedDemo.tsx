import { useState } from 'react'
import { phaseLabels } from '../../workbench/Lifecycle'
import type { Phase } from '../../workbench/Lifecycle'
import { request } from '../../api'

type Checkpoint = {
  title: string
  operator: string
  status: Phase
  incident_count: number
  incident_id: string | null
  policy_code: string
}

export function FailClosedDemo({ token }: { token: string }) {
  const [checks, setChecks] = useState<Checkpoint[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    setChecks([])
    setError('')
    try {
      const { blocked, restored } = await request<{ blocked: Checkpoint; restored: Checkpoint }>(
        '/api/fail-closed-demo', { method: 'POST' }, token,
      )
      setChecks([blocked, restored])
    } catch {
      setError('Не удалось выполнить проверку. Проверьте доступность исполнителя.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Отказ по умолчанию">
      <h2>Отказ по умолчанию</h2>
      <p>Сравните подтверждение одного черновика до и после восстановления назначения дежурного.</p>
      <button className="outline" onClick={() => void run()} disabled={busy}>
        {busy ? 'Проверяем полномочия…' : 'Проверить отказ по умолчанию'}
      </button>
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {checks.length > 0 && (
          <div className="outcome-grid">
            {checks.map(check => (
              <article key={check.policy_code} className="outcome-card">
                <h3>{check.title}</h3>
                <p>{check.operator}</p>
                <p>{phaseLabels[check.status]} · Карточек в трекере: {check.incident_count}
                  {check.incident_id && ` · ${check.incident_id}`}
                </p>
                <small>Код проверки · <code>{check.policy_code}</code></small>
              </article>
            ))}
          </div>
        )}
      </div>
    </section>
  )
}
