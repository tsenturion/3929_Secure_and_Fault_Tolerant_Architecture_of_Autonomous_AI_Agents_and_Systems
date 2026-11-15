import { useState } from 'react'
import { request } from '../../api'
import { phaseLabels } from '../../workbench/Lifecycle'
import type { Phase } from '../../workbench/Lifecycle'

type Checkpoint = {
  title: string
  operator: string
  status: Phase
  incident_count: number
  incident_id: string | null
  policy_code: string
}

export function ApprovalTimeoutDemo({ token }: { token: string }) {
  const [checks, setChecks] = useState<Checkpoint[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function compare() {
    setBusy(true)
    setChecks([])
    setError('')
    try {
      const result = await request<{ timely: Checkpoint; late: Checkpoint }>(
        '/api/approval-timeout-demo', { method: 'POST' }, token,
      )
      setChecks([result.timely, result.late])
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось сравнить сроки.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Срок согласования">
      <h2>Срок согласования</h2>
      <p>Черновик поступил в 14:12. Согласование действует до 14:22.</p>
      <button className="outline" disabled={busy} onClick={() => void compare()}>
        {busy ? 'Проверяем сроки…' : 'Сравнить подтверждения по времени'}
      </button>
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {checks.length > 0 && (
          <div className="outcome-grid">
            {checks.map(check => (
              <article className="outcome-card" key={check.policy_code}>
                <h3>{check.title}</h3>
                <p>{check.operator}</p>
                <p>{phaseLabels[check.status]} · Карточек в трекере: {check.incident_count}
                  {check.incident_id && ` · ${check.incident_id}`}
                </p>
                <small>Решение исполнителя · <code>{check.policy_code}</code></small>
              </article>
            ))}
          </div>
        )}
      </div>
    </section>
  )
}
