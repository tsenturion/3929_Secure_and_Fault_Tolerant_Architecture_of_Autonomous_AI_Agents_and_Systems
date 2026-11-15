import { useEffect, useRef, useState } from 'react'
import { phaseLabels } from '../../workbench/Lifecycle'
import type { Phase } from '../../workbench/Lifecycle'

type Stage = 'delegated' | 'reported' | 'timeout' | 'failed' | 'ready' | 'manual'
type Actor = 'diagnostic' | 'runbook' | 'coordinator'
type Source = { action: string; label: string; version: string; summary: string }
type Event = {
  elapsed_ms: number; stage: Stage; actor: Actor; task_id: string | null
  detail: string; sources: Source[]; oldest_minutes: number | null
}
export type DelegationTrace = { events: Event[] }
type Run = { id: string; status: Phase; delegation: DelegationTrace }
type Frame = { kind: 'progress'; event: Event } | { kind: 'result'; run: Run } | { kind: 'error'; detail: string }

const roles: Record<Actor, string> = {
  coordinator: 'Master Agent', diagnostic: 'Агент диагностики', runbook: 'Агент регламентов',
}
const stages: Record<Stage, string> = {
  delegated: 'Выдал задание', reported: 'Передал результат', timeout: 'Срок ожидания истёк',
  failed: 'Задание завершилось отказом', ready: 'Передал на согласование', manual: 'Передал на ручной разбор',
}
const duration = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 0 })

export function DelegationEvents({ events }: { events: Event[] }) {
  return (
    <ol className="history" aria-label="Этапы делегирования">
      {events.map((event, index) => (
        <li key={index}>
          <small>{duration.format(event.elapsed_ms)} мс · {roles[event.actor]}
            {event.task_id && <> · <code title={event.task_id}>{event.task_id.slice(0, 8)}</code></>}
          </small>
          <strong>{stages[event.stage]}</strong>
          <p>{event.detail}</p>
          {event.oldest_minutes !== null && <p>Возраст старейшего сообщения · {event.oldest_minutes} мин</p>}
          {event.sources.map(source => (
            <details key={source.action}>
              <summary>{source.label} · {source.version}</summary>
              <p>{source.summary}</p>
            </details>
          ))}
        </li>
      ))}
    </ol>
  )
}

async function followHierarchy(token: string, slow: boolean, signal: AbortSignal, present: (frame: Frame) => void) {
  const response = await fetch('/api/hierarchy/runs', {
    method: 'POST', signal,
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ slow_catalog: slow }),
  })
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(typeof body?.detail === 'string' ? body.detail : 'Не удалось запустить разбор.')
  }
  if (!response.body || !response.headers.get('content-type')?.includes('application/x-ndjson')) {
    throw new Error('Журнал выполнения недоступен.')
  }
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader()
  let buffer = ''
  let saved = false
  try {
    for (;;) {
      const next = await reader.read()
      if (next.done) {
        if (!saved) throw new Error('Разбор прервался до сохранения результата.')
        return
      }
      buffer += next.value
      const lines = buffer.split('\n')
      buffer = lines.pop() ?? ''
      for (const line of lines) {
        if (!line.trim()) continue
        const frame = JSON.parse(line) as Frame
        if (frame.kind === 'error') throw new Error(frame.detail)
        present(frame)
        if (frame.kind === 'result') saved = true
      }
    }
  } finally {
    await reader.cancel().catch(() => {})
  }
}

export function HierarchyPanel({
  token, known, canOpen, onOpen,
}: { token: string; known: { id: string; status: Phase }[]; canOpen: boolean; onOpen: (id: string) => void }) {
  const [slow, setSlow] = useState(false)
  const [events, setEvents] = useState<Event[]>([])
  const [run, setRun] = useState<Run>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const active = useRef<AbortController | null>(null)
  useEffect(() => () => active.current?.abort(), [])

  async function start() {
    const controller = new AbortController()
    active.current = controller
    setError('')
    setRun(undefined)
    setEvents([])
    setBusy(true)
    try {
      await followHierarchy(token, slow, controller.signal, frame => {
        if (frame.kind === 'progress') setEvents(previous => [...previous, frame.event])
        if (frame.kind === 'result') {
          setRun(frame.run)
          setEvents(frame.run.delegation.events)
        }
      })
    } catch (cause) {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Разбор прервался.')
    } finally {
      if (!controller.signal.aborted) setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Иерархический разбор">
      <h2>Иерархический разбор</h2>
      <label htmlFor="delegation-catalog">Ответ каталога регламентов</label>
      <select id="delegation-catalog" value={slow ? 'slow' : 'normal'} disabled={busy}
        onChange={event => setSlow(event.target.value === 'slow')}>
        <option value="normal">Штатный ответ</option>
        <option value="slow">Ответ запаздывает</option>
      </select>
      <button className="outline" disabled={busy} onClick={() => void start()}>
        {busy ? 'Выполняем задания…' : 'Запустить иерархический разбор'}
      </button>
      {error && <p className="notice" role="alert">{error}</p>}
      {events.length > 0 && <DelegationEvents events={events} />}
      {run && (
        <>
          <p className="run-status">{phaseLabels[known.find(item => item.id === run.id)?.status ?? run.status]}</p>
          <button className="outline" disabled={!canOpen} onClick={() => onOpen(run.id)}>Открыть прогон</button>
        </>
      )}
    </section>
  )
}
