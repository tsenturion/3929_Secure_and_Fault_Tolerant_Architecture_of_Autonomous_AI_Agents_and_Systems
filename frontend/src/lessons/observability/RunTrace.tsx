import { useState } from 'react'
import { request } from '../../api'

const operationLabels: Record<string, string> = {
  triage: 'Автоматический разбор',
  tool_request: 'Вызов исполнителя',
  tool_execute: 'Выполнение инструмента',
  model_decide: 'Выбор действия моделью',
  model_judge: 'Вызов модели для проверки риска',
  provider_decide: 'Запрос к провайдеру модели',
  provider_judge: 'Проверка риска у провайдера',
  policy: 'Проверка политики',
  filter: 'Фильтрация данных',
  approval_policy: 'Проверка права на согласование',
  persist_run: 'Сохранение прогона',
  issue_approval: 'Выдача токена операции',
  resolve_approval: 'Фиксация решения',
  registration: 'Результат записи инцидента',
  monitoring_snapshot: 'Получен снимок мониторинга',
  monitoring_attempt: 'Попытка чтения мониторинга',
  monitoring_source: 'Ответ сервиса мониторинга',
  runbook_search: 'Поиск в каталоге регламентов',
  monitoring_circuit: 'Состояние circuit breaker',
  registration_attempt: 'Попытка регистрации',
  coordination: 'Обмен результатами агентов',
  coordination_run: 'Разбор с координацией',
  hierarchy_run: 'Разбор Master Agent',
  hierarchy: 'Выдача и приём задания',
  delegated_task: 'Работа подчинённого агента',
  information_flow: 'Правило передачи полей',
  egress_boundary: 'Подготовка данных для исходящих каналов',
  source_policy: 'Проверка параметров источника',
  source_read: 'Чтение разрешённого источника',
}

const participants: Record<string, string> = {
  diagnostic: 'Агент диагностики', runbook: 'Агент регламентов', coordinator: 'Координатор',
}

const statusLabels = {
  pending: 'События ещё доставляются в Loki.',
  disabled: 'Для просмотра событий из Loki запустите стенд через scripts/start-observability.ps1.',
  unavailable: 'Loki временно недоступен.',
  no_trace: 'Для этого прогона доступны метки жизненного цикла.',
}

type TraceItem = {
  timestamp: string
  service: string
  kind: 'span' | 'event'
  operation: string
  result: string
  span_id: string
  parent_span_id: string | null
  started_at: string | null
  duration_ms: number | null
  provider: string | null
  check_level: string | null
  tool: string | null
  snapshot_at: string | null
  attempt: string | null
  actor: string | null
  peer: string | null
  message_id: string | null
  task_id: string | null
  sender: string | null
  recipient: string | null
  symptom: string | null
  affected_reports: number | null
}

export type TraceView = {
  trace_id: string | null
  status: keyof typeof statusLabels | 'available'
  automated_ms: number
  operator_wait_ms: number | null
  items: TraceItem[]
}

function duration(ms: number) {
  if (ms < 1000) return `${ms.toLocaleString('ru-RU', { maximumFractionDigits: 1 })} мс`
  if (ms < 60_000) return `${(ms / 1000).toLocaleString('ru-RU', { maximumFractionDigits: 1 })} с`
  const minutes = Math.floor(ms / 60_000)
  const seconds = Math.floor(ms / 1000) % 60
  return seconds ? `${minutes} мин ${seconds} с` : `${minutes} мин`
}

export function TraceDetails({ trace }: { trace: TraceView }) {
  return (
    <>
      <dl className="trace-summary">
        <div><dt>Автоматический разбор</dt><dd>{duration(trace.automated_ms)}</dd></div>
        {trace.operator_wait_ms !== null && (
          <div><dt>Ожидание дежурного</dt><dd>{duration(trace.operator_wait_ms)}</dd></div>
        )}
      </dl>
      {trace.trace_id && <p className="secondary">Трасса · <code>{trace.trace_id}</code></p>}
      {trace.status !== 'available' && <p className="secondary">{statusLabels[trace.status]}</p>}
      {trace.items.length > 0 && (
        <ol className="history trace-items">
          {trace.items.map((item, index) => (
            <li key={`${item.span_id}-${index}`}>
              <strong>{operationLabels[item.operation] ?? item.operation}</strong>
              <p>
                {new Date(item.started_at ?? item.timestamp).toLocaleTimeString('ru-RU')}
                {' · '}<code>{item.service}</code>
                {item.duration_ms !== null && <> · {duration(item.duration_ms)}</>}
              </p>
              <p>
                <code>{item.result}</code>
                {(item.tool ?? item.provider ?? item.check_level) && <> · {item.tool ?? item.provider ?? item.check_level}</>}
                {item.snapshot_at && <> · Снимок на {item.snapshot_at}</>}
                {item.attempt && <> · Попытка {item.attempt}</>}
                {item.actor && <> · {participants[item.actor] ?? item.actor}</>}
                {item.peer && item.peer !== item.actor && <> · {participants[item.peer] ?? item.peer}</>}
                {item.message_id && <> · <code title={item.message_id}>{item.message_id.slice(0, 8)}</code></>}
                {item.task_id && <> · <code title={item.task_id}>{item.task_id.slice(0, 8)}</code></>}
                {item.sender && item.recipient && <> · {item.sender} → {item.recipient}</>}
                {item.symptom && <> · {item.symptom}</>}
                {item.affected_reports !== null && <> · Обращений {item.affected_reports}</>}
              </p>
            </li>
          ))}
        </ol>
      )}
    </>
  )
}

export function RunTrace({ runId, token }: { runId: string; token: string }) {
  const [trace, setTrace] = useState<TraceView>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function load() {
    setBusy(true)
    setError('')
    try {
      setTrace(await request<TraceView>(`/api/runs/${runId}/trace`, undefined, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось открыть трассу.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="run-trace" aria-label="Трасса прогона">
      <button className="outline" disabled={busy} onClick={() => void load()}>
        {busy ? 'Загружаем трассу…' : trace ? 'Обновить трассу' : 'Открыть трассу'}
      </button>
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {trace && <TraceDetails trace={trace} />}
      </div>
    </section>
  )
}
