import { useState } from 'react'
import { request } from '../../api'
import { phaseLabels } from '../../workbench/Lifecycle'
import type { Phase } from '../../workbench/Lifecycle'

type Mode = 'centralized' | 'peer_to_peer'
type Actor = 'diagnostic' | 'runbook' | 'coordinator'
type Event = {
  at_ms: number
  code: 'catalog_wait' | 'sent' | 'stored' | 'duplicate' | 'assembled' | 'inconsistent'
  actor: Actor
  peer: Actor | null
  message_id: string | null
  evidence_count: number | null
}
export type CoordinationTrace = { mode: Mode; catalog_delay_ms: number; events: Event[] }
type CoordinatedRun = { id: string; status: Phase; coordination: CoordinationTrace; error: string | null }

const modes: Mode[] = ['centralized', 'peer_to_peer']
const titles: Record<Mode, string> = { centralized: 'Через координатора', peer_to_peer: 'Напрямую между агентами' }
const participants: Record<Actor, string> = {
  diagnostic: 'Агент диагностики', runbook: 'Агент регламентов', coordinator: 'Координатор',
}
const steps: Record<Event['code'], string> = {
  catalog_wait: 'Ждёт ответа каталога',
  sent: 'Отправил результат',
  stored: 'Сохранил результат',
  duplicate: 'Отбросил повтор',
  assembled: 'Объединил результаты',
  inconsistent: 'Обнаружено расхождение',
}
const duration = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 0 })

export function CoordinationEvents({ trace }: { trace: CoordinationTrace }) {
  return (
    <ol className="history coordination-events" aria-label={titles[trace.mode]}>
      {trace.events.map((event, index) => (
        <li key={index}>
          <small>{duration.format(event.at_ms)} мс · {participants[event.actor]}</small>
          <strong>{steps[event.code]}</strong>
          <p>
            {event.peer && event.peer !== event.actor && participants[event.peer]}
            {event.message_id && <> · <code title={event.message_id}>{event.message_id.slice(0, 8)}</code></>}
            {event.evidence_count !== null && <> · Результатов {event.evidence_count} из 2</>}
          </p>
        </li>
      ))}
    </ol>
  )
}

export function CoordinationPanel({
  token, known, canOpen, onOpen,
}: { token: string; known: { id: string; status: Phase }[]; canOpen: boolean; onOpen: (id: string) => void }) {
  const [rows, setRows] = useState<Partial<Record<Mode, CoordinatedRun | string>>>({})
  const [busy, setBusy] = useState(false)

  async function compare() {
    setRows({})
    setBusy(true)
    try {
      await Promise.all(modes.map(async mode => {
        try {
          const result = await request<CoordinatedRun>('/api/coordination/runs', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }),
          }, token)
          setRows(current => ({ ...current, [mode]: result }))
        } catch (cause) {
          const message = cause instanceof Error ? cause.message : 'Не удалось выполнить разбор.'
          setRows(current => ({ ...current, [mode]: message }))
        }
      }))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Координация агентов">
      <h2>Координация агентов</h2>
      <p>Два разбора REQ-1842. Диагностическое сообщение приходит дважды, ответ каталога запаздывает.</p>
      <button className="outline" disabled={busy} onClick={() => void compare()}>
        {busy ? 'Выполняем разбор…' : 'Сравнить координацию'}
      </button>
      {modes.some(mode => rows[mode] !== undefined) && (
        <div className="outcome-grid">
          {modes.map(mode => {
            const row = rows[mode]
            const status = row && typeof row !== 'string' && (known.find(item => item.id === row.id)?.status ?? row.status)
            return (
              <article key={mode} className="outcome-card">
                <h3>{titles[mode]}</h3>
                {typeof row === 'string' && <p className="notice" role="alert">{row}</p>}
                {row && typeof row !== 'string' && status && (
                  <>
                    <p className="run-status">{phaseLabels[status]}</p>
                    {row.error && <p className="notice">{row.error}</p>}
                    <p className="secondary">Задержка каталога · {row.coordination.catalog_delay_ms} мс</p>
                    <CoordinationEvents trace={row.coordination} />
                    <button className="outline" disabled={!canOpen} onClick={() => onOpen(row.id)}>
                      Открыть прогон
                    </button>
                  </>
                )}
              </article>
            )
          })}
        </div>
      )}
    </section>
  )
}
