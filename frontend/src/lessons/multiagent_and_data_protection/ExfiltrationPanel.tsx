import { useState } from 'react'
import { phaseLabels } from '../../workbench/Lifecycle'
import type { Phase } from '../../workbench/Lifecycle'
import type { SupportExport } from '../shield_pipeline/SupportExportForm'
import { request } from '../../api'

type CapturedBody = { input: string; [key: string]: unknown }
type Report = { run: { id: string; status: Phase }; requests: CapturedBody[] }

export function ExfiltrationPanel({ token, canOpen, onOpen }: {
  token: string; canOpen: boolean; onOpen: (id: string) => void
}) {
  const [report, setReport] = useState<Report>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function start() {
    setBusy(true)
    setError('')
    setReport(undefined)
    try {
      setReport(await request<Report>('/api/exfiltration/runs', { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Проверка не завершилась.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Предотвращение эксфильтрации данных">
      <h2>Предотвращение эксфильтрации данных</h2>
      <p>Запустите разбор обращения с вымышленным адресом покупателя. Стенд перехватит тело запроса адаптера OpenAI внутри приложения.</p>
      <button className="outline" disabled={busy} onClick={() => void start()}>
        {busy ? 'Проверяем…' : 'Проверить исходящие данные'}
      </button>
      {error && <p className="notice" role="alert">{error}</p>}
      {report && (
        <>
          <p className="run-status">{phaseLabels[report.run.status]}</p>
          {report.requests.map((body, index) => (
            <details className="run-trace" key={index}>
              <summary>Тело запроса OpenAI{report.requests.length > 1 ? ` · ${index + 1}` : ''}</summary>
              <pre className="egress-json">{JSON.stringify(body, null, 2)}</pre>
              <details>
                <summary>Расшифровать поле input</summary>
                <pre className="egress-json">{JSON.stringify(JSON.parse(body.input), null, 2)}</pre>
              </details>
            </details>
          ))}
          {report.requests.length === 0 && <p className="secondary">Прогон завершился до вызова адаптера.</p>}
          <button className="outline" disabled={!canOpen} onClick={() => onOpen(report.run.id)}>Открыть прогон</button>
        </>
      )}
    </section>
  )
}

export function SupportCard({ runId, token }: { runId: string; token: string }) {
  const [card, setCard] = useState<SupportExport>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function open() {
    setBusy(true)
    setError('')
    try {
      setCard(await request<SupportExport>(`/api/runs/${runId}/support-card`, { cache: 'no-store' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Карточка недоступна.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="boundary-results" aria-label="Закрытая карточка поддержки">
      <h3>Закрытая карточка поддержки</h3>
      <button className="outline" disabled={busy} onClick={() => card ? setCard(undefined) : void open()}>
        {card ? 'Скрыть оригинал' : busy ? 'Загружаем…' : 'Показать оригинал'}
      </button>
      {card && <dl className="trace-summary">
        <div><dt>Описание обращения</dt><dd>{card.description}</dd></div>
        {card.customer_email && <div><dt>Контакт покупателя</dt><dd>{card.customer_email}</dd></div>}
      </dl>}
      {error && <p className="notice" role="alert">{error}</p>}
    </section>
  )
}
