import { useEffect, useState, type FormEvent } from 'react'
import { request } from '../api'
import type { Phase } from './Lifecycle'
import './WorkCases.css'

export type WorkCase = {
  id: string
  symptom: 'delayed_confirmation' | 'missing_confirmation'
  title: string
  created_at: string
  revision: number
  analysis_status: Phase | null
  closed_at: string | null
  evidence: {
    snapshot_at: string
    deployment_at: string
    report_count: number
    queue_size: number
    oldest_minutes: number
    checkout_healthy: boolean
  } | null
  incident: { id: string; run_id: string; registered_at: string; priority: 'P2' } | null
}

type SupportCard = { description: string; customer_email?: string | null }
type Evidence = NonNullable<WorkCase['evidence']>

const symptomLabels: Record<WorkCase['symptom'], string> = {
  delayed_confirmation: 'Подтверждение приходит с задержкой',
  missing_confirmation: 'Подтверждение не приходит',
}

function localDateTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

function dateLabel(value: string): string {
  return new Date(value).toLocaleString('ru-RU')
}

export function CaseIntake({ token, onCreated, disabled = false }: {
  token: string; onCreated: (item: WorkCase) => void; disabled?: boolean;
}) {
  const [symptom, setSymptom] = useState<WorkCase['symptom']>('delayed_confirmation')
  const [description, setDescription] = useState('')
  const [customerEmail, setCustomerEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const item = await request<WorkCase>('/api/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          symptom,
          support: { description: description.trim(), ...(customerEmail.trim() && { customer_email: customerEmail.trim() }) },
        }),
      }, token)
      setDescription('')
      setCustomerEmail('')
      onCreated(item)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось создать обращение.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="case support-export work-case-form" onSubmit={event => void submit(event)}>
      <h2>Новое обращение</h2>
      <div>
        <label htmlFor="case-symptom">Проблема с подтверждением заказа</label>
        <select id="case-symptom" value={symptom} disabled={busy}
          onChange={event => setSymptom(event.target.value as WorkCase['symptom'])}>
          {Object.entries(symptomLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </div>
      <div>
        <label htmlFor="case-description">Описание от поддержки</label>
        <textarea id="case-description" rows={4} required maxLength={1600} value={description} disabled={busy}
          onChange={event => setDescription(event.target.value)} />
      </div>
      <div>
        <label htmlFor="case-email">Контакт покупателя (необязательно)</label>
        <input id="case-email" type="email" maxLength={254} value={customerEmail} disabled={busy}
          onChange={event => setCustomerEmail(event.target.value)} />
      </div>
      <div className="form-actions"><button className="primary" disabled={busy || disabled || !description.trim()}>
        {busy ? 'Создаём…' : 'Создать обращение'}
      </button></div>
      {error && <p className="notice" role="alert">{error}</p>}
    </form>
  )
}

function EvidenceForm({ item, token, disabled, onChange }: {
  item: WorkCase; token: string; disabled: boolean; onChange: (item: WorkCase) => void
}) {
  const current = item.evidence
  const [snapshotAt, setSnapshotAt] = useState(localDateTime(current?.snapshot_at ?? new Date().toISOString()))
  const [deploymentAt, setDeploymentAt] = useState(localDateTime(current?.deployment_at ?? ''))
  const [reportCount, setReportCount] = useState(String(current?.report_count ?? ''))
  const [queueSize, setQueueSize] = useState(String(current?.queue_size ?? ''))
  const [oldestMinutes, setOldestMinutes] = useState(String(current?.oldest_minutes ?? ''))
  const [checkout, setCheckout] = useState(current ? current.checkout_healthy ? 'healthy' : 'unhealthy' : '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    const snapshot = new Date(snapshotAt)
    const deployment = new Date(deploymentAt)
    if (!Number.isFinite(snapshot.getTime()) || !Number.isFinite(deployment.getTime()) || !checkout) {
      setError('Укажите время снимка и развёртывания, затем подтвердите состояние оформления заказа.')
      return
    }
    if (deployment > snapshot) {
      setError('Укажите снимок, полученный после развёртывания.')
      return
    }
    setBusy(true)
    try {
      const evidence: Evidence = {
        snapshot_at: snapshot.toISOString(),
        deployment_at: deployment.toISOString(),
        report_count: Number(reportCount),
        queue_size: Number(queueSize),
        oldest_minutes: Number(oldestMinutes),
        checkout_healthy: checkout === 'healthy',
      }
      const updated = await request<WorkCase>(`/api/cases/${encodeURIComponent(item.id)}/evidence`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ revision: item.revision, evidence }),
      }, token)
      onChange(updated)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось сохранить факты.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="support-export work-case-form" onSubmit={event => void submit(event)}>
      <h3>Проверенные факты</h3>
      <div className="work-case-fields">
        <div><label htmlFor="case-snapshot">Время снимка мониторинга</label>
          <input id="case-snapshot" type="datetime-local" required value={snapshotAt} disabled={busy || disabled}
            onChange={event => setSnapshotAt(event.target.value)} /></div>
        <div><label htmlFor="case-deployment">Время развёртывания</label>
          <input id="case-deployment" type="datetime-local" required value={deploymentAt} disabled={busy || disabled}
            onChange={event => setDeploymentAt(event.target.value)} /></div>
        <div><label htmlFor="case-reports">Жалоб за последние 10 минут</label>
          <input id="case-reports" type="number" min={0} max={1_000_000_000} step={1} required value={reportCount} disabled={busy || disabled}
            onChange={event => setReportCount(event.target.value)} /></div>
        <div><label htmlFor="case-queue">Сообщений в очереди</label>
          <input id="case-queue" type="number" min={0} max={1_000_000_000} step={1} required value={queueSize} disabled={busy || disabled}
            onChange={event => setQueueSize(event.target.value)} /></div>
        <div><label htmlFor="case-oldest">Старейшее сообщение, мин</label>
          <input id="case-oldest" type="number" min={0} max={1_000_000_000} step={1} required value={oldestMinutes} disabled={busy || disabled}
            onChange={event => setOldestMinutes(event.target.value)} /></div>
        <div><label htmlFor="case-checkout">Оформление заказа</label>
          <select id="case-checkout" value={checkout} required disabled={busy || disabled}
            onChange={event => setCheckout(event.target.value)}>
            <option value="">Выберите состояние</option>
            <option value="healthy">Работает</option><option value="unhealthy">Есть сбои</option>
          </select></div>
      </div>
      <div className="form-actions"><button className="primary" disabled={busy || disabled}>
        {busy ? 'Сохраняем…' : 'Сохранить факты'}
      </button></div>
      {error && <p className="notice" role="alert">{error}</p>}
    </form>
  )
}

export function CaseDetails({ item, token, canManage, disabled, onChange }: {
  item: WorkCase; token: string; canManage: boolean; disabled: boolean; onChange: (item: WorkCase) => void
}) {
  const [card, setCard] = useState<{ caseId: string; value: SupportCard }>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => { setCard(undefined); setError('') }, [item.id, canManage])
  const visibleCard = card?.caseId === item.id ? card.value : undefined

  async function openCard() {
    setBusy(true)
    setError('')
    try {
      const value = await request<SupportCard>(`/api/cases/${encodeURIComponent(item.id)}/support-card`, {
        cache: 'no-store',
      }, token)
      setCard({ caseId: item.id, value })
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Карточка недоступна.')
    } finally {
      setBusy(false)
    }
  }

  async function closeCase() {
    setBusy(true)
    setError('')
    try {
      onChange(await request<WorkCase>(`/api/cases/${encodeURIComponent(item.id)}/close`, { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось закрыть обращение.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case work-case-details" aria-label="Карточка обращения">
      <h2>{item.title}</h2>
      <p className="secondary"><code>{item.id}</code> · Создано {dateLabel(item.created_at)}</p>
      <p>{item.closed_at ? `Закрыто ${dateLabel(item.closed_at)}` : 'Открыто'} · Редакция {item.revision}</p>
      {item.evidence && <dl className="trace-summary">
        <div><dt>Снимок</dt><dd>{dateLabel(item.evidence.snapshot_at)}</dd></div>
        <div><dt>Развёртывание</dt><dd>{dateLabel(item.evidence.deployment_at)}</dd></div>
        <div><dt>Обращений</dt><dd>{item.evidence.report_count}</dd></div>
        <div><dt>Очередь</dt><dd>{item.evidence.queue_size}</dd></div>
        <div><dt>Старейшее сообщение</dt><dd>{item.evidence.oldest_minutes} мин</dd></div>
        <div><dt>Оформление заказа</dt><dd>{item.evidence.checkout_healthy ? 'Работает' : 'Есть сбои'}</dd></div>
      </dl>}
      {canManage && <div className="work-case-support">
        <button type="button" className="outline" disabled={busy || disabled}
          onClick={() => visibleCard ? setCard(undefined) : void openCard()}>
          {visibleCard ? 'Скрыть карточку поддержки' : busy ? 'Загружаем…' : 'Показать карточку поддержки'}
        </button>
        {visibleCard && <dl className="trace-summary">
          <div><dt>Описание</dt><dd>{visibleCard.description}</dd></div>
          {visibleCard.customer_email && <div><dt>Контакт покупателя</dt><dd>{visibleCard.customer_email}</dd></div>}
        </dl>}
      </div>}
      {canManage && !item.closed_at && <>
        <EvidenceForm key={`${item.id}:${item.revision}`} item={item} token={token} disabled={disabled || busy} onChange={onChange} />
        <button type="button" className="outline" disabled={busy || disabled} onClick={() => void closeCase()}>
          {busy ? 'Закрываем…' : 'Закрыть обращение'}
        </button>
      </>}
      {error && <p className="notice" role="alert">{error}</p>}
    </section>
  )
}
