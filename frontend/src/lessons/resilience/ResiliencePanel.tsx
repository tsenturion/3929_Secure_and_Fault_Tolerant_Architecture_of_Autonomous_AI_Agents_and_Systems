import { useState } from 'react'
import { request } from '../../api'

type DurableState = {
  status: 'awaiting_approval' | 'completed'
  incident_count: number
  incident_id: string | null
  receipt_saved: boolean
}

type Recovery = { after_failure: DurableState; after_retry: DurableState }
type Report = { scenario_id: string; before_commit: Recovery; after_commit: Recovery }

function Snapshot({ title, state }: { title: string; state: DurableState }) {
  return (
    <li>
      <strong>{title}</strong>
      <p>{state.status === 'completed' ? 'Разбор завершён' : 'Ожидает согласования'}</p>
      <p>Записей в трекере · {state.incident_count}{state.incident_id && ` · ${state.incident_id}`}</p>
      <p>Результат операции · {state.receipt_saved ? 'сохранён' : 'отсутствует'}</p>
    </li>
  )
}

function RecoveryCard({ title, note, recovery }: { title: string; note: string; recovery: Recovery }) {
  return (
    <article className="outcome-card">
      <h3>{title}</h3>
      <ol>
        <Snapshot title="После остановки процесса" state={recovery.after_failure} />
        <Snapshot title="После повтора в новом процессе" state={recovery.after_retry} />
      </ol>
      <p className="secondary">{note}</p>
    </article>
  )
}

export function ResiliencePanel({ token }: { token: string }) {
  const [report, setReport] = useState<Report>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function run() {
    setBusy(true)
    setError('')
    setReport(undefined)
    try {
      setReport(await request<Report>('/api/resilience/demo', { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Проверка восстановления завершилась ошибкой.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Восстановление после сбоя">
      <h2>Восстановление после сбоя</h2>
      <p>Профиль PostgreSQL позволяет проверить повтор регистрации с тем же согласованием и ключом операции.</p>
      <button className="outline" disabled={busy} onClick={() => void run()}>
        {busy ? 'Проверяем восстановление…' : 'Проверить восстановление'}
      </button>
      {error && <p className="error" role="alert">{error}</p>}
      {report && (
        <div className="outcome-grid" aria-label={`Результаты для ${report.scenario_id}`}>
          <RecoveryCard title="Сбой до фиксации"
            note="PostgreSQL откатила транзакцию. Повтор по сохранённому согласованию создал инцидент."
            recovery={report.before_commit} />
          <RecoveryCard title="Ответ потерян после фиксации"
            note="Повтор вернул сохранённый номер инцидента. В трекере осталась одна запись."
            recovery={report.after_commit} />
        </div>
      )}
    </section>
  )
}
