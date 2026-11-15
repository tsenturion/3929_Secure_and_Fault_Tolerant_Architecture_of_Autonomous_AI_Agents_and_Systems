import { useState } from 'react'

export type SupportExport = { description: string; customer_email: string | null }
export type FilterCheck = { boundary: 'input' | 'output'; code: string; detail: string }

const sample = {
  description: 'Покупатели видят оплаченные заказы, но письма о подтверждении задерживаются. Контакт для уточнения: buyer-1842@example.invalid.',
  customer_email: 'buyer-1842@example.invalid',
}

export function SupportExportForm({ busy, modelReady, onRun }: {
  busy: boolean
  modelReady: boolean
  onRun: (report: SupportExport, invalidOutput: boolean) => void
}) {
  const [description, setDescription] = useState('')
  const [email, setEmail] = useState('')
  const [invalidOutput, setInvalidOutput] = useState(false)

  return (
    <section className="case outcome-comparison" aria-label="Фильтрация входов и выходов">
      <h2>Фильтрация входов и выходов</h2>
      <p>Добавьте выгрузку поддержки к REQ-1842 и посмотрите, какие поля попадут в разбор.</p>
      <form className="support-export" onSubmit={event => {
        event.preventDefault()
        onRun({ description, customer_email: email.trim() || null }, invalidOutput)
      }}>
        <div>
          <label htmlFor="support-description">Описание из выгрузки</label>
          <textarea id="support-description" value={description} maxLength={1600} required rows={3}
            disabled={busy} onChange={event => setDescription(event.target.value)} />
          <small>{description.length} / 1600 символов</small>
        </div>
        <div>
          <label htmlFor="support-email">Контакт в выгрузке</label>
          <input id="support-email" type="email" maxLength={254} value={email}
            disabled={busy} onChange={event => setEmail(event.target.value)} />
        </div>
        <label className="sample-option">
          <input type="checkbox" checked={invalidOutput} disabled={busy}
            onChange={event => setInvalidOutput(event.target.checked)} />
          Проверить ответ с недопустимым приоритетом
        </label>
        <div className="form-actions">
          <button className="outline" type="button" disabled={busy}
            onClick={() => { setDescription(sample.description); setEmail(sample.customer_email) }}>
            Подставить учебную выгрузку
          </button>
          <button className="primary" disabled={busy || !description.trim() || (!modelReady && !invalidOutput)}>
            {busy ? 'Выполняется разбор…' : 'Проверить фильтрацию'}
          </button>
        </div>
      </form>
    </section>
  )
}

export function FilterTrace({ checks }: { checks: FilterCheck[] }) {
  if (!checks.length) return null
  return (
    <section className="boundary-results" aria-label="Результаты фильтрации">
      <h3>Результаты фильтрации</h3>
      <ul>
        {checks.map((check, index) => (
          <li key={index}>
            <small>{check.boundary === 'input' ? 'Вход' : 'Выход'}</small>
            <strong><code>{check.code}</code></strong>
            <p>{check.detail}</p>
          </li>
        ))}
      </ul>
    </section>
  )
}
