import { useState } from 'react'

export type Phase =
  | 'observe' | 'reason' | 'act' | 'awaiting_approval' | 'approval_expired' | 'completed'
  | 'needs_review' | 'rejected' | 'manual_handoff' | 'manual_completed' | 'failed'

export type LifecycleEvent = { phase: Phase; title: string; detail: string; at: string }
export type Decision = 'approve' | 'reject' | 'take_over' | 'complete_manual' | 'fail_manual'

export const phaseLabels: Record<Phase, string> = {
  observe: 'Наблюдение',
  reason: 'Решение',
  act: 'Действие',
  awaiting_approval: 'Ожидает согласования',
  approval_expired: 'Согласование истекло',
  completed: 'Завершён',
  needs_review: 'Требуется ручной разбор',
  manual_handoff: 'Принято в ручной разбор',
  manual_completed: 'Завершено вручную',
  failed: 'Закрыто с ошибкой',
  rejected: 'Отклонён',
}

export function Lifecycle({ events }: { events: LifecycleEvent[] }) {
  const [visibleThrough, setVisibleThrough] = useState<number>()
  const end = visibleThrough ?? events.length - 1

  return (
    <section className="lifecycle">
      <div className="timeline-heading">
        <h3>Жизненный цикл</h3>
        <div className="timeline-controls">
          {visibleThrough === undefined ? (
            <button className="outline" onClick={() => setVisibleThrough(0)}>Пройти по шагам</button>
          ) : (
            <>
              <button className="outline" onClick={() => setVisibleThrough(undefined)}>Вся история</button>
              <button className="outline" disabled={end >= events.length - 1}
                onClick={() => setVisibleThrough(end + 1)}>Следующий этап</button>
            </>
          )}
        </div>
      </div>
      <ol className="timeline">
        {events.slice(0, end + 1).map((event, index) => (
          <li key={index} data-phase={event.phase}>
            <small>{phaseLabels[event.phase]}</small>
            <strong>{event.title}</strong>
            <p>{event.detail}</p>
          </li>
        ))}
      </ol>
    </section>
  )
}
