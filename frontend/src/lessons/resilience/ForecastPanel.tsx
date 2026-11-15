import { useEffect, useRef, useState } from 'react'
import { request } from '../../api'

type Score = { detected: number; missed: number; false_alarms: number; lead_minutes: number | null }
type Flow = { requests: number; p95_minutes: number; background_checks: number }
type Point = {
  minute: number; backlog: number; controlled_backlog: number; arrivals: number; delay: number
  probability: number | null; controlled_probability: number | null
  overload: boolean; lstm_alert: boolean; throttled: boolean
}
type Report = {
  window_minutes: number; horizon_minutes: number; overload_delay: number
  train_days: number; validation_days: number; test_days: number; threshold: number
  lstm: Score; rule: Score; baseline: Flow; controlled: Flow; timeline: Point[]
}
type Replay = {
  active: boolean; minute: number | null; probability: number | null
  throttled: boolean; background_seconds: number
}

const minutes = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 })
const percentage = new Intl.NumberFormat('ru-RU', { style: 'percent', maximumFractionDigits: 0 })
function hour(minute: number) {
  return `${17 + Math.floor(minute / 60)}:${String(minute % 60).padStart(2, '0')}`
}

function Timeline({ report, selected }: { report: Report; selected: number }) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const points = report.timeline

  useEffect(() => {
    const node = canvas.current
    const ctx = node?.getContext('2d')
    if (!node || !ctx) return
    const left = 50, right = node.width - 32, top = 25, center = 160, bottom = 264
    const x = (minute: number) => left + minute * (right - left) / (points.length - 1)
    const maxQueue = Math.max(1, ...points.map(point => Math.max(point.backlog, point.controlled_backlog)))
    const queueY = (backlog: number) => center - 16 - (center - top - 16) * backlog / maxQueue
    const riskY = (risk: number) => bottom - (bottom - center - 25) * risk

    function line(color: string, y: (point: Point) => number | null) {
      if (!ctx) return
      ctx.strokeStyle = color
      ctx.lineWidth = 2
      ctx.beginPath()
      let started = false
      for (const point of points) {
        const position = y(point)
        if (position === null) continue
        if (started) ctx.lineTo(x(point.minute), position)
        else ctx.moveTo(x(point.minute), position)
        started = true
      }
      ctx.stroke()
    }
    ctx.clearRect(0, 0, node.width, node.height)
    ctx.fillStyle = '#ddede3'
    for (const point of points) {
      if (point.throttled) ctx.fillRect(x(point.minute), top, x(1) - x(0) + 0.2, bottom - top)
    }
    ctx.strokeStyle = '#c3ced8'
    for (const y of [top, center - 16, bottom]) {
      ctx.beginPath()
      ctx.moveTo(left, y)
      ctx.lineTo(right, y)
      ctx.stroke()
    }
    ctx.font = '13px system-ui'
    ctx.fillStyle = '#47596b'
    ctx.fillText(String(maxQueue), 7, top + 4)
    ctx.fillText('0', 30, center - 12)
    ctx.fillText('100%', 7, riskY(1) + 4)
    ctx.fillText('0%', 20, bottom + 3)
    for (let minute = 0; minute < points.length; minute += 30) {
      ctx.fillText(hour(minute), x(minute) - 18, bottom + 23)
    }
    ctx.setLineDash([5, 5])
    line('#927568', () => riskY(report.threshold))
    ctx.setLineDash([])
    line('#4a617a', point => queueY(point.backlog))
    line('#147552', point => queueY(point.controlled_backlog))
    line('#a94726', point => point.probability === null ? null : riskY(point.probability))
    ctx.fillStyle = '#963930'
    for (const point of points) {
      if (point.overload) ctx.fillRect(x(point.minute), center + 2, x(1) - x(0), 4)
    }
    ctx.strokeStyle = '#4c5667'
    ctx.lineWidth = 1
    ctx.beginPath()
    ctx.moveTo(x(selected), top)
    ctx.lineTo(x(selected), bottom)
    ctx.stroke()
  }, [points, report.threshold, selected])

  return <canvas ref={canvas} width={820} height={296} className="forecast-chart"
    aria-label="Очередь, вероятность перегрузки, сигналы порога и интервалы снижения фоновой нагрузки" role="img" />
}

function ScoreRow({ label, score }: { label: string; score: Score }) {
  return <tr><th scope="row">{label}</th><td>{score.detected}</td><td>{score.missed}</td>
    <td>{score.false_alarms}</td><td>{score.lead_minutes === null ? '—' : `${minutes.format(score.lead_minutes)} мин`}</td></tr>
}

export function ForecastPanel({ token, canReplay }: { token: string; canReplay: boolean }) {
  const [report, setReport] = useState<Report>()
  const [replay, setReplay] = useState<Replay>()
  const [selected, setSelected] = useState(0)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    void Promise.all([
      request<Report>('/api/forecast', { signal: controller.signal }, token),
      request<Replay>('/api/forecast/replay', { signal: controller.signal }, token),
    ]).then(([result, state]) => {
      setReport(result)
      setReplay(state)
      setSelected(state.minute ?? result.timeline.find(point => point.overload)?.minute ?? 0)
    }).catch(cause => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Прогноз недоступен.')
    })
    return () => controller.abort()
  }, [token])

  useEffect(() => {
    if (!replay?.active) return
    const controller = new AbortController()
    let timer: number | undefined
    async function update() {
      try {
        const state = await request<Replay>('/api/forecast/replay', { signal: controller.signal }, token)
        setReplay(state)
        if (state.minute !== null) setSelected(state.minute)
        if (state.active) timer = window.setTimeout(() => void update(), 1000)
      } catch {
        if (!controller.signal.aborted) {
          setError('Не удалось обновить состояние воспроизведения.')
          timer = window.setTimeout(() => void update(), 3000)
        }
      }
    }
    timer = window.setTimeout(() => void update(), 1000)
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [replay?.active, token])

  async function start() {
    setBusy(true)
    setError('')
    try {
      const state = await request<Replay>('/api/forecast/replay', { method: 'POST' }, token)
      setReplay(state)
      if (state.minute !== null) setSelected(state.minute)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось запустить вечерний пик.')
    } finally {
      setBusy(false)
    }
  }

  const point = report?.timeline[selected]
  return (
    <section className="case outcome-comparison" aria-label="Прогноз перегрузки">
      <h2>Прогноз перегрузки очереди</h2>
      {error && <p className="notice" role="alert">{error}</p>}
      {!report && !error && <p className="secondary">Загружаем результаты проверки LSTM.</p>}
      {report && point && (
        <>
          <p>Горизонт · {report.horizon_minutes} мин. Модель анализирует последние {report.window_minutes} мин.
            Порог тревоги LSTM · {percentage.format(report.threshold)}. Перегрузка начинается при оценке ожидания от {report.overload_delay} мин.</p>
          <div className="metrics-table">
            <table>
              <caption>Качество на {report.test_days} отложенных днях</caption>
              <thead><tr><th scope="col">Метод</th><th scope="col">Обнаружено</th><th scope="col">Пропущено</th>
                <th scope="col">Ложные тревоги</th><th scope="col">Среднее предупреждение</th></tr></thead>
              <tbody><ScoreRow label="LSTM" score={report.lstm} /><ScoreRow label="Порог по задержке" score={report.rule} /></tbody>
            </table>
          </div>
          <figure className="forecast-figure">
            <figcaption>Вечерний пик · {report.baseline.requests.toLocaleString('ru-RU')} новых обращений</figcaption>
            <Timeline report={report} selected={selected} />
            <p className="forecast-legend">
              <span>Очередь по обычному расписанию</span><span>Очередь с управлением</span>
              <span>Вероятность по LSTM</span><span>Сигнал порога по задержке</span><span>Паузы фоновой диагностики</span>
            </p>
            <label htmlFor="forecast-minute">Момент на шкале · {hour(selected)}</label>
            <input id="forecast-minute" type="range" min={0} max={report.timeline.length - 1}
              value={selected} disabled={replay?.active} onChange={event => setSelected(Number(event.target.value))} />
            <p>{point.probability === null ? 'Собирается окно для прогноза' : `Вероятность · ${percentage.format(point.probability)}`}
              {' · '}Очередь · {point.backlog} → {point.controlled_backlog}{' · '}Поступило за минуту · {point.arrivals}
              {' · '}Оценка ожидания · {minutes.format(point.delay)} мин</p>
            {(point.lstm_alert || point.overload || point.throttled) && <p>
              {[point.lstm_alert && 'Тревога LSTM', point.overload && 'Порог задержки достигнут',
                point.throttled && 'Фоновая диагностика замедлена'].filter(Boolean).join(' · ')}
            </p>}
          </figure>
          <p>95-й процентиль ожидания · <strong>{report.baseline.p95_minutes} → {report.controlled.p95_minutes} мин</strong>.
            Фоновые проверки · {report.baseline.background_checks} → {report.controlled.background_checks}.</p>
          {canReplay && <button className="outline" disabled={busy || replay?.active} onClick={() => void start()}>
            {replay?.active ? 'Вечерний пик идёт' : 'Запустить вечерний пик'}
          </button>}
          {replay?.active && <p role="status" className="notice">
            {replay.throttled ? 'Снижена частота фоновой диагностики' : 'Обычная частота фоновой диагностики'}
            {' · '}{replay.background_seconds} с между проверками
            {replay.probability !== null && ` · Текущий прогноз ${percentage.format(replay.probability)}`}
          </p>}
        </>
      )}
    </section>
  )
}
