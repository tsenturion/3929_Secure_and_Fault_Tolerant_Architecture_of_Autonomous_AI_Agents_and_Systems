import { useState } from 'react'
import { request } from '../../api'

type Certificate = { service: string; san: string; serial: string; expires_at: string }
type Proof = {
  proof: { service: string; certificate_serial: string; verified: boolean }
  replay_blocked: boolean
}

export function AgentIdentityDemo({ token, enabled, tpm }: {
  token: string; enabled: boolean; tpm: boolean
}) {
  const [certificate, setCertificate] = useState<Certificate>()
  const [previous, setPrevious] = useState<Certificate>()
  const [proof, setProof] = useState<Proof>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function inspect() {
    setBusy(true)
    setError('')
    try {
      const current = await request<Certificate>('/api/workload-identity', undefined, token)
      if (certificate && certificate.serial !== current.serial) setPrevious(certificate)
      setCertificate(current)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось проверить сертификат.')
    } finally {
      setBusy(false)
    }
  }

  async function prove() {
    setBusy(true)
    setProof(undefined)
    setError('')
    try {
      setProof(await request<Proof>('/api/workload-identity/tpm-proof', { method: 'POST' }, token))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось подтвердить ключ TPM.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="case outcome-comparison agent-identity" aria-label="Идентификация агента">
      <h2>Идентификация агента</h2>
      {enabled ? (
        <div className="form-actions agent-identity-actions">
          <button className="outline" disabled={busy} onClick={() => void inspect()}>Проверить сертификат</button>
          {tpm && (
            <button className="outline" disabled={busy} onClick={() => void prove()}>Подтвердить ключ TPM</button>
          )}
        </div>
      ) : (
        <p>
          В этой вкладке режим сертификатов выключен. Откройте кабинет Docker по адресу из вывода{' '}
          <code>scripts/start-agent-identity.ps1</code>.
        </p>
      )}
      <div aria-live="polite" aria-busy={busy}>
        {error && <p className="notice" role="alert">{error}</p>}
        {certificate && (
          <article className="outcome-card">
            <h3>Сертификат, принятый исполнителем</h3>
            <p>Служба · <code>{certificate.san}</code></p>
            {previous && <p>Предыдущий номер · <code>{previous.serial}</code></p>}
            <p>Серийный номер · <code>{certificate.serial}</code></p>
            <p>Действует до {new Date(certificate.expires_at).toLocaleString('ru-RU')}</p>
          </article>
        )}
        {proof && (
          <article className="outcome-card">
            <h3>Подпись программного TPM</h3>
            <p>{proof.proof.verified ? 'Исполнитель подтвердил владение ключом.' : 'Ключ не подтверждён.'}</p>
            <p>{proof.replay_blocked ? 'Повтор той же подписи отклонён.' : 'Исполнитель принял повтор подписи.'}</p>
            <p>Сертификат соединения · <code>{proof.proof.certificate_serial}</code></p>
          </article>
        )}
      </div>
    </section>
  )
}
