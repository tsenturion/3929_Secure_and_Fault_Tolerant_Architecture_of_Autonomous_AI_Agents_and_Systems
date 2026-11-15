import { useState } from 'react'
import { request } from '../../api'

const checkLabels = {
  verified: 'Совпадает с контрольной точкой',
  unanchored: 'Контрольная точка отсутствует',
  pending_checkpoint: 'Новые записи ожидают контрольной точки',
  event_modified: 'Содержимое или связь записи изменились',
  sequence_gap: 'Нарушена последовательность записей',
  checkpoint_mismatch: 'История расходится с контрольной точкой',
  truncated: 'Удалён конец журнала',
}

const actionLabels: Record<string, string> = {
  case_created: 'Открыто рабочее обращение',
  case_evidence_updated: 'Обновлены данные обращения',
  case_closed: 'Закрыто рабочее обращение',
  case_support_opened: 'Открыта закрытая карточка поддержки',
  tool_call: 'Вызов инструмента',
  run_saved: 'Сохранение прогона',
  approve_draft: 'Согласование черновика',
  register_incident: 'Регистрация инцидента',
  reject_draft: 'Отклонение черновика',
  take_over: 'Передача в ручной разбор',
  finish_manual: 'Завершение ручного разбора',
  expire_approval: 'Окончание срока согласования',
}

const decisionLabels = {
  allow: 'Разрешено',
  deny: 'Отклонено',
  record: 'Зафиксировано',
  replay: 'Возвращён сохранённый результат',
}

type Check = {
  day: string
  code: keyof typeof checkLabels
  records: number
  anchored_through: number
  first_difference: number | null
}
type AuditEvent = {
  at: string
  service: string
  operator: string | null
  run_id: string
  action: string
  decision: keyof typeof decisionLabels
  result: string
  priority: string | null
  queue: string | null
  incident_id: string | null
  tool: string | null
}
type AuditRecord = {
  day: string
  sequence: number
  previous_hash: string
  event_hash: string
  event: AuditEvent
}
type History = { checks: Check[]; events: AuditRecord[] }
type Comparison = { original: Check; modified: Check; truncated: Check; approval: AuditEvent }

function CheckCard({ title, check }: { title: string; check: Check }) {
  return (
    <article className="outcome-card">
      <h3>{title}</h3>
      <p>{checkLabels[check.code]} · <code>{check.code}</code></p>
      <p>Записей · {check.records} · Контрольная точка №{check.anchored_through || '—'}</p>
      {check.first_difference !== null && <p>Первое расхождение · Запись №{check.first_difference}</p>}
    </article>
  )
}

export function AuditPanel({ token, scenario }: { token: string; scenario: string }) {
  const [history, setHistory] = useState<History>()
  const [comparison, setComparison] = useState<Comparison>()
  const [busy, setBusy] = useState<'history' | 'demo'>()
  const [error, setError] = useState('')

  async function load(mode: 'history' | 'demo') {
    setBusy(mode)
    setError('')
    try {
      if (mode === 'history') {
        setHistory(await request<History>(`/api/audit?scenario_id=${encodeURIComponent(scenario)}`, undefined, token))
      } else {
        setComparison(await request<Comparison>('/api/audit-demo', { method: 'POST' }, token))
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось проверить журнал.')
    } finally {
      setBusy(undefined)
    }
  }

  return (
    <section className="case outcome-comparison audit-panel" aria-label="Целостность аудита">
      <h2>Целостность аудита</h2>
      <div className="form-actions audit-actions">
        <button className="outline" disabled={Boolean(busy)} onClick={() => void load('history')}>
          {busy === 'history' ? 'Проверяем журнал…' : 'Проверить журнал обращения'}
        </button>
        {scenario === 'REQ-1842' && (
          <button className="outline" disabled={Boolean(busy)} onClick={() => void load('demo')}>
            {busy === 'demo' ? 'Проверяем копии…' : 'Сравнить копии журнала'}
          </button>
        )}
      </div>
      <div aria-live="polite" aria-busy={Boolean(busy)}>
        {error && <p className="notice" role="alert">{error}</p>}
        {history && (
          <>
            {history.checks.length === 0 && <p>В журнале обращения пока нет событий.</p>}
            <div className="outcome-grid">
              {history.checks.map(check => <CheckCard key={check.day} title={`${check.day} · UTC`} check={check} />)}
            </div>
            {history.events.length > 0 && (
              <ol className="history audit-events">
                {history.events.map(({ day, sequence, event, previous_hash, event_hash }) => (
                  <li key={`${day}-${sequence}`}>
                    <strong>№{sequence} · {actionLabels[event.action] ?? event.action}</strong>
                    <p>{new Date(event.at).toLocaleString('ru-RU')} · {event.operator ?? event.service}</p>
                    <p>{decisionLabels[event.decision]} · <code>{event.result}</code>{event.tool && <> · <code>{event.tool}</code></>}</p>
                    {event.priority && <p>{event.priority}{event.queue && ` · ${event.queue}`}{event.incident_id && ` · ${event.incident_id}`}</p>}
                    <details>
                      <summary>Связь с предыдущей записью</summary>
                      <p>Предыдущий хеш · <code>{previous_hash}</code></p>
                      <p>Хеш записи · <code>{event_hash}</code></p>
                    </details>
                  </li>
                ))}
              </ol>
            )}
          </>
        )}
        {comparison && (
          <>
            <p>В исходном журнале <code>{comparison.approval.operator}</code> подтвердил {comparison.approval.priority} в {new Date(comparison.approval.at).toLocaleTimeString('ru-RU')}.</p>
            <div className="outcome-grid">
              <CheckCard title="Исходный журнал" check={comparison.original} />
              <CheckCard title="Изменено время согласования" check={comparison.modified} />
              <CheckCard title="Удалены последние записи" check={comparison.truncated} />
            </div>
          </>
        )}
      </div>
    </section>
  )
}
