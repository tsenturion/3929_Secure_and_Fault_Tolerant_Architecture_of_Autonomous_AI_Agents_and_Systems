import { useEffect, useRef, useState } from 'react'
import { request } from '../../api'
import { TraceDetails } from './RunTrace'
import type { TraceView } from './RunTrace'
import { toolLabels } from '../../workbench/toolLabels'

type Evidence = {
  day: string
  sequence: number
  at: string
  run_id: string
  saved_run: boolean
  trace_id: string | null
  operator: string | null
  action: string
  result: string
  tool: string | null
  snapshot_at: string | null
}
type Alert = {
  id: string
  kind: 'tool_rate' | 'write_denials' | 'budget'
  service: string
  count: number
  threshold: number
  evidence: Evidence[]
  tool: string | null
  baseline_per_minute: number | null
  repeated_snapshot_reads: number
  budget_metric: 'steps' | 'tools' | 'blocked' | null
  budget_limit: number | null
}
type Report = {
  source: 'live' | 'demo'
  alerts: Alert[]
  demo_traces: Record<string, TraceView>
}

const time = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const rate = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 2 })

function title(alert: Alert) {
  if (alert.kind === 'write_denials') return 'Серия отказов при записи'
  if (alert.kind === 'tool_rate') return 'Всплеск вызовов инструмента'
  if (alert.budget_metric === 'blocked') return 'Вызов заблокирован по лимиту'
  return alert.budget_limit !== null && alert.count >= alert.budget_limit
    ? 'Бюджет прогона исчерпан' : 'Бюджет прогона близок к исчерпанию'
}

function AlertSummary({ alert }: { alert: Alert }) {
  if (alert.kind === 'write_denials') {
    return <p>Отказов за минуту · {alert.count} · Порог · {alert.threshold}</p>
  }
  if (alert.kind === 'tool_rate') {
    return (
      <>
        {alert.tool && <p>{toolLabels[alert.tool] ?? alert.tool}</p>}
        <p>За минуту · {alert.count} · Среднее за предыдущие 5 минут · {rate.format(alert.baseline_per_minute ?? 0)}</p>
        <p>Порог · от {alert.threshold} за минуту и рост как минимум вдвое</p>
        {alert.repeated_snapshot_reads > 0 && <p>Чтений одного снимка · {alert.repeated_snapshot_reads}</p>}
      </>
    )
  }
  return alert.budget_metric === 'blocked'
    ? <p>Отклонено по ограничению · {alert.count}</p>
    : <p>{alert.budget_metric === 'steps' ? 'Шаги агента' : 'Вызовы исполнителя'} · {alert.count} из {alert.budget_limit}</p>
}

export function AnomalyPanel({ token, scenario, revision }: { token: string; scenario: string; revision: string }) {
  const [source, setSource] = useState<Report['source']>('live')
  const [reload, setReload] = useState(0)
  const [report, setReport] = useState<Report>()
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const [trace, setTrace] = useState<TraceView>()
  const [traceBusy, setTraceBusy] = useState(false)
  const [traceError, setTraceError] = useState('')
  const traceRequest = useRef<AbortController | undefined>(undefined)
  const traceSection = useRef<HTMLElement | null>(null)
  const revisionKey = source === 'live' ? revision : ''

  useEffect(() => {
    const controller = new AbortController()
    let next: number | undefined
    setBusy(true)
    async function load() {
      const demo = source === 'demo'
      const url = demo ? '/api/anomalies/demo' : `/api/anomalies?scenario_id=${encodeURIComponent(scenario)}`
      try {
        const value = await request<Report>(url, { signal: controller.signal, method: demo ? 'POST' : 'GET' }, token)
        if (!controller.signal.aborted) {
          setReport(value)
          setError('')
        }
      } catch (cause) {
        if (!controller.signal.aborted) {
          setError(cause instanceof Error ? cause.message : 'Не удалось проверить журнал.')
        }
      } finally {
        if (!controller.signal.aborted) {
          setBusy(false)
          if (!demo) next = window.setTimeout(() => void load(), 5000)
        }
      }
    }
    void load()
    return () => {
      controller.abort()
      window.clearTimeout(next)
    }
  }, [source, scenario, revisionKey, reload, token])

  useEffect(() => () => traceRequest.current?.abort(), [])
  useEffect(() => {
    if (trace) traceSection.current?.scrollIntoView({ block: 'nearest' })
  }, [trace])

  function switchSource(value: Report['source']) {
    traceRequest.current?.abort()
    setTrace(undefined)
    setTraceError('')
    setTraceBusy(false)
    setSource(value)
    setReload(count => count + 1)
  }

  async function openTrace(runId: string) {
    traceRequest.current?.abort()
    setTraceError('')
    const sample = report?.demo_traces[runId]
    if (sample) {
      setTrace(sample)
      return
    }
    const controller = new AbortController()
    traceRequest.current = controller
    setTraceBusy(true)
    setTrace(undefined)
    try {
      const value = await request<TraceView>(`/api/runs/${runId}/trace`, { signal: controller.signal }, token)
      if (!controller.signal.aborted) setTrace(value)
    } catch (cause) {
      if (!controller.signal.aborted) {
        setTraceError(cause instanceof Error ? cause.message : 'Не удалось открыть трассу.')
      }
    } finally {
      if (!controller.signal.aborted) setTraceBusy(false)
    }
  }

  const data = report?.source === source ? report : undefined
  return (
    <section className="case outcome-comparison anomaly-panel" aria-label="Оповещения об аномалиях">
      <h2>Оповещения об аномалиях</h2>
      <div className="form-actions anomaly-actions">
        <button className="outline" aria-pressed={source === 'live'} onClick={() => switchSource('live')}>Живые оповещения</button>
        {scenario === 'REQ-1842' && (
          <button className="outline" disabled={source === 'demo' && busy} aria-pressed={source === 'demo'}
            onClick={() => switchSource('demo')}>Проверить всплеск очереди</button>
        )}
      </div>
      <div aria-live="polite">
        {error && <p className="notice" role="alert">{error}</p>}
        {busy && <p>Проверяем события…</p>}
        {data && !busy && <p>{data.source === 'demo' ? 'Учебный прогон' : 'Активные оповещения'} · {data.alerts.length}</p>}
      </div>
      {data && (
        <div className="anomaly-list">
          {data.alerts.map(alert => (
            <article className="outcome-card" key={alert.id}>
              <h3>{title(alert)}</h3>
              <p className="secondary"><code>{alert.service}</code></p>
              <AlertSummary alert={alert} />
              <details>
                <summary>События аудита</summary>
                <ol className="history">
                  {alert.evidence.map(item => (
                    <li key={`${item.day}-${item.sequence}`}>
                      <p>
                        Запись №{item.sequence} · {item.day} · {time.format(new Date(item.at))}
                        {item.operator && <> · <code>{item.operator}</code></>} · <code>{item.result}</code>
                        {item.snapshot_at && <> · Снимок на {item.snapshot_at}</>}
                      </p>
                      {item.trace_id && item.saved_run && (
                        <button className="outline" disabled={traceBusy} onClick={() => void openTrace(item.run_id)}>
                          Открыть трассу
                        </button>
                      )}
                    </li>
                  ))}
                </ol>
              </details>
            </article>
          ))}
        </div>
      )}
      {traceBusy && <p role="status">Загружаем трассу…</p>}
      {traceError && <p className="notice" role="alert">{traceError}</p>}
      {trace && (
        <section ref={traceSection} className="outcome-card anomaly-trace" aria-label="Трасса оповещения">
          <h3>Трасса оповещения</h3>
          <TraceDetails trace={trace} />
          <button className="outline" onClick={() => setTrace(undefined)}>Закрыть трассу</button>
        </section>
      )}
    </section>
  )
}
