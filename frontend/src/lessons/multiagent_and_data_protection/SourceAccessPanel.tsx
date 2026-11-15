import { useState } from 'react'
import { request } from '../../api'

type TraceEvent = { operation: 'source_policy' | 'source_read'; result: string }
type Check = {
  action: 'get_service_status' | 'find_incident_runbook'
  reference: string
  code: string
  message: string
  observation: string | null
  trace: TraceEvent[]
}
type Report = { trace_id: string; checks: Check[] }

const sourceLabels = {
  get_service_status: 'Мониторинг очереди',
  find_incident_runbook: 'Каталог регламентов',
}

export function SourceAccessPanel({ token }: { token: string }) {
  const [report, setReport] = useState<Report>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function run() {
    setBusy(true)
    setError('')
    setReport(undefined)
    try {
      setReport(await request<Report>('/api/source-access-demo', { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Проверка источников не завершилась.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Защита от SSRF и ограничение доступа к файлам">
      <h2>Защита от SSRF и ограничение доступа к файлам</h2>
      <p>Сравните чтение по идентификатору с подстановкой ссылки или пути в параметры инструмента.</p>
      <button className="outline" disabled={busy} onClick={() => void run()}>
        {busy ? 'Проверяем источники…' : 'Проверить доступ к источникам'}
      </button>
      <div aria-live="polite">
        {error && <p className="notice" role="alert">{error}</p>}
        {report && <>
          <p className="secondary">Трасса · <code>{report.trace_id}</code></p>
          <div className="outcome-grid">
            {report.checks.map(check => {
              const read = check.trace.find(event => event.operation === 'source_read')
              return (
                <article className="outcome-card" key={`${check.action}:${check.reference}`}>
                  <h3>{sourceLabels[check.action]}</h3>
                  <p><code>{check.reference}</code></p>
                  <p><strong>{read ? read.result === 'ok' ? 'Источник прочитан' : 'Ошибка чтения' : 'Отклонено до чтения'}</strong> · <code>{check.code}</code></p>
                  <p>{check.observation ?? check.message}</p>
                  <details>
                    <summary>События проверки</summary>
                    <ol>{check.trace.map(event => (
                      <li key={event.operation}>{event.operation === 'source_read' ? 'Чтение источника' : 'Проверка параметров'} · <code>{event.result}</code></li>
                    ))}</ol>
                  </details>
                </article>
              )
            })}
          </div>
        </>}
      </div>
    </section>
  )
}
