import { useEffect, useState } from 'react'
import { ApiError, request } from '../../api'

type Status = 'ok' | 'degraded' | 'unknown'
type Check = { status: Status; code: string }
type Model = Check & { provider: string; detail: string | null; last_response_at: string | null }
type Health = {
  checked_at: string
  status: Status
  storage: Check
  monitoring: Check
  catalog: Check
  runbook: Check
  manual: Check
  model: Model
}

const states = { ok: 'Работает', degraded: 'Сбой', unknown: 'Не подтверждено' }
const providerNames: Record<string, string> = { openai: 'OpenAI', gigachat: 'GigaChat', qwen: 'Qwen' }
const details: Record<string, string> = {
  storage_ready: 'Исполнитель читает хранилище прогонов.',
  storage_unavailable: 'Хранилище недоступно.',
  snapshot_ok: 'Получен свежий снимок очереди.',
  stale_snapshot: 'Полученный снимок устарел.',
  source_unavailable: 'Источник метрик недоступен.',
  timeout: 'Источник не ответил вовремя.',
  catalog_alive: 'Каталог отвечает на проверку живости.',
  catalog_unreachable: 'Каталог не ответил на проверку живости.',
  catalog_embedded: 'В локальном запуске каталог встроен в исполнитель.',
  runbook_found: 'Поиск вернул опубликованный RB-NOTIFY-07.',
  runbook_not_found: 'RB-NOTIFY-07 отсутствует в индексе поиска.',
  runbook_unavailable: 'Поиск по каталогу недоступен.',
  invalid_runbook: 'Полученный регламент не прошёл проверку.',
  manual_available: 'Дежурный может принять и закрыть обращение вручную.',
  assignment_missing: 'У очереди нет назначенного дежурного.',
  not_assigned: 'Назначение дежурного не подтверждено.',
  policy_unavailable: 'Расписание дежурных недоступно.',
  model_unavailable: 'Модель или шлюз недоступны.',
  model_unverified: 'Конфигурация доступна. Недавнего ответа модели пока нет.',
  model_response_ok: 'Последний ответ модели прошёл проверку.',
  model_response_unavailable: 'Последняя попытка обращения к модели завершилась ошибкой.',
  model_response_invalid: 'Последний ответ модели отклонён проверкой формата.',
}

const time = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' })

function Row({ label, check, detail }: { label: string; check: Check; detail?: string }) {
  return (
    <tr>
      <th scope="row">{label}</th>
      <td><strong className={`health-${check.status}`}>{states[check.status]}</strong></td>
      <td>{detail ?? details[check.code] ?? check.code}</td>
    </tr>
  )
}

async function checkHttp(path: string, signal: AbortSignal) {
  return (await fetch(path, { cache: 'no-store', signal })).status
}

function HttpProbeRow({ label, status }: { label: string; status?: number }) {
  const state = status === 200 ? 'ok' : status === undefined ? 'unknown' : 'degraded'
  return <Row label={label} check={{ status: state, code: '' }}
    detail={status === undefined ? 'Ответ пока не получен.' : `HTTP ${status}`} />
}

export function HealthPanel({ token }: { token: string }) {
  const [health, setHealth] = useState<Health>()
  const [live, setLive] = useState<number>()
  const [ready, setReady] = useState<number>()
  const [error, setError] = useState('')
  const [deferred, setDeferred] = useState(false)
  const [busy, setBusy] = useState(false)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    let next: number | undefined
    async function load() {
      const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(12000)])
      const [liveness, readiness] = await Promise.allSettled([
        checkHttp('/api/health/live', signal),
        checkHttp('/api/health/ready', signal),
      ])
      if (controller.signal.aborted) return
      setLive(liveness.status === 'fulfilled' ? liveness.value : undefined)
      setReady(readiness.status === 'fulfilled' ? readiness.value : undefined)
      next = window.setTimeout(() => void load(), 15000)
    }
    void load()
    return () => {
      controller.abort()
      window.clearTimeout(next)
    }
  }, [reload])

  useEffect(() => {
    const controller = new AbortController()
    let next: number | undefined
    async function load(background: boolean) {
      setBusy(true)
      const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(12000)])
      const [report] = await Promise.allSettled([
        request<Health>(background ? '/api/health/functional?background=true' : '/api/health/functional',
          { signal, cache: 'no-store' }, token),
      ])
      if (controller.signal.aborted) return
      let interval = 15000
      const reason = report.status === 'rejected' ? report.reason : undefined
      const byForecast = reason instanceof ApiError && reason.code === 'forecast_deferred'
      setDeferred(byForecast)
      if (byForecast) {
        interval = Math.max(1, reason.retryAfter ?? 15) * 1000
        setError('')
      } else {
        setHealth(report.status === 'fulfilled' ? report.value : undefined)
        setError(report.status === 'rejected' ? 'Функциональную проверку сейчас выполнить не удалось.' : '')
      }
      setBusy(false)
      next = window.setTimeout(() => void load(true), interval)
    }
    void load(reload === 0)
    return () => {
      controller.abort()
      window.clearTimeout(next)
    }
  }, [token, reload])

  return (
    <section className="case outcome-comparison" aria-label="Функциональное здоровье">
      <h2>Функциональное здоровье</h2>
      <button className="outline" disabled={busy} onClick={() => setReload(value => value + 1)}>
        {busy ? 'Проверяем…' : 'Обновить проверки'}
      </button>
      {health && <p className="secondary">
        Проверено в {time.format(new Date(health.checked_at))} · {health.status === 'ok' ? 'Рабочий маршрут доступен' : 'Обнаружена деградация'}
      </p>}
      {error && <p className="notice" role="alert">{error}</p>}
      {deferred && <p className="notice" role="status">Фоновая диагностика отложена по прогнозу. Ручная проверка доступна.</p>}
      <div className="metrics-table">
        <table>
          <thead><tr><th scope="col">Проверка</th><th scope="col">Состояние</th><th scope="col">Результат</th></tr></thead>
          <tbody>
            <HttpProbeRow label="Живость API" status={live} />
            <HttpProbeRow label="Готовность API" status={ready} />
            {health && (
              <>
                <Row label="Хранилище" check={health.storage} />
                <Row label="Чтение очереди" check={health.monitoring} />
                <Row label="Живость каталога" check={health.catalog} />
                <Row label="Поиск регламента" check={health.runbook} />
                <Row label="Ручной маршрут" check={health.manual} />
                <Row label={`Модель · ${providerNames[health.model.provider] ?? health.model.provider}`}
                  check={health.model}
                  detail={(health.model.detail ?? details[health.model.code]) +
                    (health.model.last_response_at ? ` · ${time.format(new Date(health.model.last_response_at))}` : '')} />
              </>
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}
