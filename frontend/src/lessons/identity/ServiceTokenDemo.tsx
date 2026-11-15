import { useState } from 'react'
import { request } from '../../api'

type Check = { status: number; code: string | null }
type Demo = {
  lifetime_seconds: number
  fresh: Check
  monitoring: Check
  expired: Check
  renewed: Check | null
  tool_result: { code: string; message: string; observation: { source: string } | null } | null
}

function CheckResult({ title, check }: { title: string; check: Check }) {
  return (
    <article className="outcome-card">
      <h3>{title}</h3>
      <p>HTTP {check.status}{check.code && <> · <code>{check.code}</code></>}</p>
    </article>
  )
}

export function ServiceTokenDemo({ token, enabled }: { token: string; enabled: boolean }) {
  const [demo, setDemo] = useState<Demo>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function run() {
    setBusy(true)
    setError('')
    setDemo(undefined)
    try {
      setDemo(await request<Demo>('/api/service-token-demo', { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось проверить сервисные токены.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison" aria-label="Эфемерные токены">
      <h2>Эфемерные токены</h2>
      {enabled ? (
        <>
          <p>Исполнитель проверяет, для какого сервиса выдан токен. Затем агент дожидается истечения токена и повторяет чтение очереди с новым.</p>
          <button className="outline" disabled={busy} onClick={() => void run()}>
            {busy ? 'Ждём истечения токена…' : 'Проверить срок и получателя токена'}
          </button>
        </>
      ) : (
        <p>Для демонстрации запустите стенд с Keycloak через <code>scripts/start-iam.ps1</code>.</p>
      )}
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {demo && (
          <>
            <p>Срок действия токена агента · {demo.lifetime_seconds} с</p>
            <div className="outcome-grid">
              <CheckResult title="Свежий токен агента" check={demo.fresh} />
              <CheckResult title="Токен для мониторинга" check={demo.monitoring} />
              <CheckResult title="Токен агента после ожидания" check={demo.expired} />
              {demo.renewed && <CheckResult title="Повтор с новым токеном" check={demo.renewed} />}
            </div>
            {demo.tool_result && (
              <p>
                <strong>Чтение REQ-1842</strong> · {demo.tool_result.message}
                {demo.tool_result.observation && <> · {demo.tool_result.observation.source}</>}
              </p>
            )}
          </>
        )}
      </div>
    </section>
  )
}
