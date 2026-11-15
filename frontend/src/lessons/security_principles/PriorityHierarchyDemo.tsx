import { useState } from 'react'
import { request } from '../../api'
import { phaseLabels } from '../../workbench/Lifecycle'
import type { Phase } from '../../workbench/Lifecycle'
import { PublishedFields } from '../../workbench/PublishedFields'
import type { Publication } from '../../workbench/PublishedFields'

type Checkpoint = {
  title: string
  operator: string
  status: Phase
  incident_count: number
  incident_id: string | null
  policy_code: string
}

type Comparison = { blocked: Checkpoint; approved: Checkpoint; publication: Publication }

export function PriorityHierarchyDemo({ token }: { token: string }) {
  const [result, setResult] = useState<Comparison>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function compare() {
    setBusy(true)
    setResult(undefined)
    setError('')
    try {
      setResult(await request<Comparison>('/api/priority-hierarchy-demo', { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось сравнить черновики.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Иерархия приоритетов">
      <h2>Иерархия приоритетов</h2>
      <p>Поддержка просит добавить контакты покупателей. На стенде дежурный подтверждает два варианта черновика.</p>
      <p className="secondary">Политика данных → полномочия и подтверждение → рекомендация агента</p>
      <button className="outline" disabled={busy} onClick={() => void compare()}>
        {busy ? 'Проверяем черновики…' : 'Сравнить решения по черновикам'}
      </button>
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {result && (
          <div className="outcome-grid">
            {[result.blocked, result.approved].map(check => (
              <article className="outcome-card" key={check.policy_code}>
                <h3>{check.title}</h3>
                <p>{check.operator}</p>
                <p>{phaseLabels[check.status]} · Карточек в трекере: {check.incident_count}
                  {check.incident_id && ` · ${check.incident_id}`}
                </p>
                <small>Решение исполнителя · <code>{check.policy_code}</code></small>
                {check.incident_id && <PublishedFields publication={result.publication} />}
              </article>
            ))}
          </div>
        )}
      </div>
    </section>
  )
}
