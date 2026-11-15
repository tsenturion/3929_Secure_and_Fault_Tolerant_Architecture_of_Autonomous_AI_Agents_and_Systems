import { useEffect, useState } from 'react'
import { request } from '../../api'
import { toolLabels } from '../../workbench/toolLabels'

type ToolMinutes = 5 | 15 | 60
type ToolMetrics = {
  tool: string
  calls: number
  calls_per_minute: number
  results: Record<string, number>
  minutes: number[]
}
type Metrics = {
  source: 'live' | 'demo'
  observed_at: string
  outcome_hours: number
  cases: {
    closed: number
    agent: number
    manual: number
    failed: number
    success_rate: number | null
    agent_rate: number | null
  }
  tool_window_minutes: ToolMinutes
  tool_window_start: string
  tool_calls: number
  tool_calls_per_minute: number
  tools: ToolMetrics[]
}

const rate = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 2 })
const percent = new Intl.NumberFormat('ru-RU', { style: 'percent', maximumFractionDigits: 1 })
const time = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit' })

function FrequencyChart({ metric, report }: { metric: ToolMetrics; report: Metrics }) {
  const max = Math.max(1, ...metric.minutes)
  const start = Date.parse(report.tool_window_start)
  const end = Date.parse(report.observed_at)
  return (
    <figure className="metrics-chart">
      <figcaption>Вызовы по минутам · {toolLabels[metric.tool] ?? metric.tool}</figcaption>
      <div className="metrics-chart-bars" role="img"
        aria-label={`${metric.calls} вызовов за ${report.tool_window_minutes} мин, максимум ${Math.max(...metric.minutes)} в минуту`}>
        {metric.minutes.map((count, index) => (
          <div key={index} className="metrics-minute"
            title={`${time.format(start + index * 60_000)}–${time.format(start + (index + 1) * 60_000)} · ${count} вызовов`}>
            <span style={{ height: `${count ? 100 * count / max : 0}%` }} />
          </div>
        ))}
      </div>
      <div className="metrics-chart-axis"><span>{time.format(start)}</span><span>{time.format(end)}</span></div>
    </figure>
  )
}

export function MetricsPanel({ token, revision, scope = 'course' }: {
  token: string; revision: string; scope?: 'course' | 'work';
}) {
  const [window, setWindow] = useState<ToolMinutes>(15)
  const [source, setSource] = useState<Metrics['source']>('live')
  const [refresh, setRefresh] = useState(0)
  const [selected, setSelected] = useState('get_service_status')
  const [report, setReport] = useState<Metrics>()
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const revisionKey = source === 'live' ? revision : ''

  useEffect(() => {
    const controller = new AbortController()
    setBusy(true)
    setError('')
    const endpoint = source === 'demo' ? '/api/metrics/demo' : `/api/metrics?tool_minutes=${window}&scope=${scope}`
    void request<Metrics>(endpoint, { signal: controller.signal }, token)
      .then(data => {
        if (!controller.signal.aborted) setReport(data)
      })
      .catch(cause => {
        if (!controller.signal.aborted) {
          setError(cause instanceof Error ? cause.message : 'Не удалось загрузить метрики.')
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false)
      })
    return () => controller.abort()
  }, [source, window, refresh, revisionKey, token, scope])

  const visibleReport = report?.source === source && (source === 'demo' || report.tool_window_minutes === window)
    ? report : undefined
  const activeTool = visibleReport?.tools.find(item => item.tool === selected) ?? visibleReport?.tools[0]
  return (
    <section className="case outcome-comparison metrics-panel" aria-label="Ключевые метрики">
      <h2>{scope === 'work' ? 'Метрики рабочей очереди' : 'Ключевые метрики'}</h2>
      <div className="metrics-toolbar">
        <div className="form-actions">
          {scope === 'course' && <>
            <button className="outline" aria-pressed={source === 'live'} onClick={() => setSource('live')}>Живые данные</button>
            <button className="outline" aria-pressed={source === 'demo'} onClick={() => setSource('demo')}>Пример смены</button>
          </>}
          <button className="outline" disabled={busy} onClick={() => setRefresh(value => value + 1)}>Обновить метрики</button>
        </div>
        {source === 'live' && (
          <div>
            <label htmlFor="metric-window">Окно вызовов</label>
            <select id="metric-window" value={window} onChange={e => setWindow(Number(e.target.value) as ToolMinutes)}>
              <option value={5}>5 мин</option>
              <option value={15}>15 мин</option>
              <option value={60}>60 мин</option>
            </select>
          </div>
        )}
      </div>
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {busy && !visibleReport && <p>Загружаем метрики…</p>}
        {visibleReport && (
          <>
            <p>{source === 'demo' ? 'Учебная выборка смены поддержки · Задержка почтовой очереди'
              : `Результаты за ${visibleReport.outcome_hours} ч · Срез на ${time.format(new Date(visibleReport.observed_at))}`}</p>
            <dl className="metrics-summary">
              <div><dt>{scope === 'work' ? 'Обработано обращений' : 'Закрыто обращений'}</dt><dd>{visibleReport.cases.closed}</dd></div>
              <div><dt>Доля успешных разборов</dt><dd>{visibleReport.cases.success_rate === null ? '—' : percent.format(visibleReport.cases.success_rate)}</dd></div>
              <div><dt>{scope === 'work' ? 'Доля автоматических разборов' : 'Доля агентного маршрута'}</dt><dd>{visibleReport.cases.agent_rate === null ? '—' : percent.format(visibleReport.cases.agent_rate)}</dd></div>
              <div><dt>Вызовов в минуту</dt><dd>{rate.format(visibleReport.tool_calls_per_minute)}</dd></div>
            </dl>
            <p>{scope === 'work' ? 'Автоматически' : 'Агентом'} · {visibleReport.cases.agent} · Вручную · {visibleReport.cases.manual} · С ошибкой · {visibleReport.cases.failed}</p>
            <p>Вызовов за {visibleReport.tool_window_minutes} мин · {visibleReport.tool_calls}</p>
            {activeTool ? (
              <>
                <label htmlFor="metric-tool">Инструмент на графике</label>
                <select id="metric-tool" value={activeTool.tool} onChange={e => setSelected(e.target.value)}>
                  {visibleReport.tools.map(item => <option key={item.tool} value={item.tool}>{toolLabels[item.tool] ?? item.tool}</option>)}
                </select>
                <FrequencyChart metric={activeTool} report={visibleReport} />
                <div className="metrics-table">
                  <table>
                    <thead><tr><th>Инструмент</th><th>Вызовов</th><th>В минуту</th><th>Исходы</th></tr></thead>
                    <tbody>
                      {visibleReport.tools.map(item => (
                        <tr key={item.tool}>
                          <th scope="row">{toolLabels[item.tool] ?? item.tool}</th>
                          <td>{item.calls}</td>
                          <td>{rate.format(item.calls_per_minute)}</td>
                          <td>{Object.entries(item.results).map(([code, count]) => <span key={code}><code>{code}</code> {count}</span>)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : <p>В выбранном окне вызовов пока нет.</p>}
          </>
        )}
      </div>
    </section>
  )
}
