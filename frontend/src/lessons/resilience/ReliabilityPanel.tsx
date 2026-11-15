import { useState } from 'react'
import { request } from '../../api'
import { phaseLabels } from '../../workbench/Lifecycle'
import type { Phase } from '../../workbench/Lifecycle'

type CircuitState = 'closed' | 'open' | 'half_open'
export type MonitoringTrace = { entry_state: CircuitState; final_state: CircuitState; attempts: string[] }

const stages = {
  transient: 'Разовый сбой HTTP 503',
  first_timeout: 'Первое чтение исчерпало попытки',
  second_timeout: 'Второе чтение исчерпало попытки',
  skipped: 'Новый запрос во время паузы',
  probe: 'Пробное чтение после паузы',
  recovered: 'Следующее штатное чтение',
}
const breakerLabels: Record<CircuitState, string> = {
  closed: 'Закрыт', open: 'Открыт', half_open: 'Полуоткрыт',
}
const attemptLabels: Record<string, string> = {
  ok: 'снимок получен', timeout: 'таймаут', transport_error: 'ошибка соединения',
  invalid_snapshot: 'неверный формат снимка',
}
type Step = {
  stage: keyof typeof stages
  status: Phase
  fresh_metrics: boolean
  monitoring: MonitoringTrace
}
type Report = { attempt_timeout_ms: number; budget_ms: number; cooldown_seconds: number; steps: Step[] }

function transition(trace: MonitoringTrace) {
  const first = breakerLabels[trace.entry_state]
  return trace.entry_state === trace.final_state ? first : `${first} → ${breakerLabels[trace.final_state]}`
}

function attempts(trace: MonitoringTrace) {
  return trace.attempts.map(code => attemptLabels[code] ?? code.replace('http_', 'HTTP ')).join(' → ') || '0 вызовов'
}

export function MonitoringDetails({ trace }: { trace: MonitoringTrace }) {
  return (
    <section className="boundary-results" aria-label="Чтение мониторинга">
      <h3>Чтение мониторинга</h3>
      <p>Circuit breaker · {transition(trace)}</p>
      <p>Попытки · {attempts(trace)}</p>
    </section>
  )
}

export function ReliabilityPanel({ token }: { token: string }) {
  const [report, setReport] = useState<Report>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function run() {
    setReport(undefined)
    setBusy(true)
    setError('')
    try {
      setReport(await request<Report>('/api/reliability/demo', { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось проверить чтение мониторинга.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Надёжность мониторинга">
      <h2>Надёжность мониторинга</h2>
      <button className="outline" disabled={busy} onClick={() => void run()}>
        {busy ? 'Проверяем мониторинг…' : 'Проверить повторы и circuit breaker'}
      </button>
      {error && <p className="notice" role="alert">{error}</p>}
      {report && (
        <>
          <p>Учебный таймаут · {report.attempt_timeout_ms} мс на попытку · {report.budget_ms} мс на чтение.
            Пауза {report.cooldown_seconds} с перед пробой показана в ускоренном режиме.</p>
          <div className="metrics-table">
            <table>
              <thead>
                <tr><th scope="col">Событие</th><th scope="col">Попытки</th><th scope="col">Circuit breaker</th><th scope="col">Результат</th></tr>
              </thead>
              <tbody>
                {report.steps.map(step => (
                  <tr key={step.stage}>
                    <th scope="row">{stages[step.stage]}</th>
                    <td>{attempts(step.monitoring)}</td>
                    <td>{transition(step.monitoring)}</td>
                    <td>{step.fresh_metrics ? 'Получены свежие метрики' : `Нет свежих метрик · ${phaseLabels[step.status]}`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  )
}
