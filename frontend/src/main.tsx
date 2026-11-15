import { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Lifecycle, phaseLabels } from './workbench/Lifecycle'
import type { Decision, LifecycleEvent, Phase } from './workbench/Lifecycle'
import { OutcomeComparison } from './lessons/agent_lifecycle/OutcomeComparison'
import { FailClosedDemo } from './lessons/security_principles/FailClosedDemo'
import { ZeroTrustDemo } from './lessons/security_principles/ZeroTrustDemo'
import { ServiceTokenDemo } from './lessons/identity/ServiceTokenDemo'
import { AgentIdentityDemo } from './lessons/identity/AgentIdentityDemo'
import { InteragentDemo } from './lessons/identity/InteragentDemo'
import { TransactionTokenDemo } from './lessons/identity/TransactionTokenDemo'
import { AuditPanel } from './lessons/observability/AuditPanel'
import { RunTrace } from './lessons/observability/RunTrace'
import { MetricsPanel } from './lessons/observability/MetricsPanel'
import { AnomalyPanel } from './lessons/observability/AnomalyPanel'
import { ResiliencePanel } from './lessons/resilience/ResiliencePanel'
import { MonitoringDetails, ReliabilityPanel } from './lessons/resilience/ReliabilityPanel'
import { HealthPanel } from './lessons/resilience/HealthPanel'
import { ForecastPanel } from './lessons/resilience/ForecastPanel'
import { CoordinationEvents, CoordinationPanel } from './lessons/multiagent_and_data_protection/CoordinationPanel'
import type { CoordinationTrace } from './lessons/multiagent_and_data_protection/CoordinationPanel'
import { DelegationEvents, HierarchyPanel } from './lessons/multiagent_and_data_protection/HierarchyPanel'
import type { DelegationTrace } from './lessons/multiagent_and_data_protection/HierarchyPanel'
import { InformationFlow } from './lessons/multiagent_and_data_protection/InformationFlow'
import type { FlowCheck, FlowData } from './lessons/multiagent_and_data_protection/InformationFlow'
import { ExfiltrationPanel, SupportCard } from './lessons/multiagent_and_data_protection/ExfiltrationPanel'
import { SourceAccessPanel } from './lessons/multiagent_and_data_protection/SourceAccessPanel'
import type { MonitoringTrace } from './lessons/resilience/ReliabilityPanel'
import { PriorityHierarchyDemo } from './lessons/security_principles/PriorityHierarchyDemo'
import { RegistrationChecksDemo } from './lessons/security_principles/RegistrationChecksDemo'
import { ApprovalTimeoutDemo } from './lessons/shield_pipeline/ApprovalTimeoutDemo'
import { ShieldTrace } from './lessons/shield_pipeline/ShieldTrace'
import type { ShieldCheck } from './lessons/shield_pipeline/ShieldTrace'
import { FilterTrace, SupportExportForm } from './lessons/shield_pipeline/SupportExportForm'
import type { FilterCheck, SupportExport } from './lessons/shield_pipeline/SupportExportForm'
import { PublishedFields } from './workbench/PublishedFields'
import type { Publication } from './workbench/PublishedFields'
import { CaseDetails, CaseIntake } from './workbench/WorkCases'
import type { WorkCase } from './workbench/WorkCases'
import { ApiError, request } from './api'
import type { Identity } from './api'
import './style.css'

type Mode = 'fixed' | 'agent'
type Scenario = { id: string; title: string; received_at: string; report: string; goal: string; source: string }
type ModelConfig = {
  provider: string
  problem: string | null
  service_auth_mode: 'static' | 'oauth' | 'certificate' | 'mtls_oauth'
  tpm_enabled: boolean
}
type Fault = 'monitoring_timeout' | 'stale_monitoring' | 'repeated_monitoring' | 'oversized_observation' | 'model_unavailable'
type Observation = { source: string; observed_at: string; summary: string }
type Threat = 'prompt_injection' | 'memory_poisoning' | 'tool_misuse' | 'data_exfiltration'
type ThreatCase = { id: Threat; title: string; situation: string; expectation: string }
type RunSummary = { id: string; status: Phase; started_at: string; threat: Threat | null }
type IncidentField = 'affected_reports' | 'technical_evidence' | 'customer_contacts'
type ApprovalGrant = { token: string; idempotency_key: string }
type PendingApproval = { runId: string; grant: ApprovalGrant }
const incidentFieldLabels: Record<IncidentField, string> = {
  affected_reports: 'число обращений',
  technical_evidence: 'технические сведения о задержке',
  customer_contacts: 'контакты покупателей',
}
type Run = {
  id: string
  scenario_id: string
  status: Phase
  provider: string | null
  degradation: 'model_unavailable' | 'model_timeout' | null
  manual_registration_available: boolean
  manual_evidence: { action: string; label: string; observation: Observation }[]
  monitoring: MonitoringTrace | null
  coordination: CoordinationTrace | null
  delegation: DelegationTrace | null
  information: FlowData
  flow_checks: FlowCheck[]
  incident_id: string | null
  publication: Publication | null
  approval_block: { code: string; message: string; at: string } | null
  approval_deadline: string | null
  shield_checks: ShieldCheck[]
  filter_checks: FilterCheck[]
  support_card_available: boolean
  case_revision: number | null
  review_required: boolean
  lifecycle: { events: LifecycleEvent[] }
  threat: Threat | null
  boundary_decisions: { threat: Threat; title: string; detail: string }[]
  steps: {
    action: string
    label: string
    selected_by: 'route' | 'model' | 'rule' | 'operator'
    reason: string
    observation: Observation | null
    executor_code: string | null
    decision_provider: string | null
  }[]
  recommendation: {
    category: string
    title: string
    detail: string
    queue: string | null
    priority: 'P1' | 'P2' | null
    incident_fields: IncidentField[]
  }
  error: string | null
}

const providerNames: Record<string, string> = {
  openai: 'OpenAI',
  gigachat: 'GigaChat',
  qwen: 'Qwen',
}

const decisionSources = {
  route: 'Фиксированный маршрут',
  model: 'Выбор модели',
  rule: 'Правило стенда',
  operator: 'Запрос дежурного',
}

const threatNames: Record<Threat, string> = {
  prompt_injection: 'Prompt injection',
  memory_poisoning: 'Memory poisoning',
  tool_misuse: 'Tool misuse',
  data_exfiltration: 'Data exfiltration',
}

function ManualIncidentForm({
  verified, busy, onManual,
}: { verified: boolean; busy: boolean; onManual: (priority?: 'P2') => void }) {
  const [priority, setPriority] = useState<'' | 'P2'>('')
  return (
    <form className="approval" onSubmit={event => {
      event.preventDefault()
      if (priority && verified) onManual(priority)
    }}>
      <button type="button" className="outline" disabled={busy} onClick={() => onManual()}>
        {verified ? 'Проверить источники снова' : 'Проверить источники'}
      </button>
      {verified && (
        <div>
          <p>Очередь · Уведомления</p>
          <label htmlFor="manual-priority">Приоритет инцидента</label>
          <select id="manual-priority" value={priority} disabled={busy}
            onChange={event => setPriority(event.target.value === 'P2' ? 'P2' : '')}>
            <option value="">Выберите приоритет</option>
            <option value="P2">P2</option>
          </select>
          <button className="primary" disabled={busy || !priority}>Подготовить черновик</button>
        </div>
      )}
    </form>
  )
}

function RunPanel({
  mode, result, busy, error, disabled, onRun, resolving, resolutionError, retryApproval, onResolve, onRefresh, onManual, token, canReadSupport, work = false, canRun = true,
}: {
  mode: Mode
  result?: Run
  busy: boolean
  error?: string
  disabled: boolean
  onRun: () => void
  resolving?: boolean
  resolutionError?: string
  retryApproval?: boolean
  onResolve?: (decision: Decision) => void
  onRefresh?: () => void
  onManual?: (priority?: 'P2') => void
  token: string
  canReadSupport: boolean
  work?: boolean
  canRun?: boolean
}) {
  const isAgent = mode === 'agent'
  const [now, setNow] = useState(() => Date.now())
  const deadline = result?.approval_deadline ? Date.parse(result.approval_deadline) : null
  const waiting = result?.status === 'awaiting_approval'
  const deadlineReached = waiting && deadline !== null && now >= deadline

  useEffect(() => {
    if (!waiting || deadline === null) return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [waiting, deadline])

  useEffect(() => {
    if (deadlineReached && !resolving && !busy) onRefresh?.()
  }, [deadlineReached, result?.id, resolving, busy])
  return (
    <article className="panel">
      <header className="panel-header">
        {!work && <p className="overline">{isAgent ? 'Ограниченная автономия' : 'Детерминированный процесс'}</p>}
        <h2>{work ? 'Результат диагностики' : isAgent ? 'Автономный агент' : 'Фиксированный маршрут'}</h2>
        {!work && <p className="secondary">
          {isAgent
            ? 'Модель выбирает следующее действие по наблюдениям. Агент может читать данные и подготовить рекомендацию.'
            : 'Программа читает источники в заданном порядке. Итог выводится из собранных фактов.'}
        </p>}
        {canRun && <button className={isAgent ? 'primary' : 'outline'} disabled={disabled || busy} onClick={onRun}>
          {busy ? 'Выполняется разбор…' : work ? 'Запустить разбор' : isAgent ? 'Запустить агента' : 'Выполнить маршрут'}
        </button>}
      </header>
      <div className="run-body" aria-live="polite" aria-busy={busy}>
        {error && <p className="notice">{error}</p>}
        {!result && !error && <p className="secondary">{busy ? 'Собираем наблюдения.' : 'Здесь появится история действий.'}</p>}
        {result && (
          <>
            <section className={`verdict ${result.recommendation.category}`}>
              <h3>{result.recommendation.title}</h3>
              <p>{result.recommendation.detail}</p>
              {result.threat && <small>Защитный прогон · {threatNames[result.threat]}</small>}
              {result.recommendation.queue && <small>Очередь · {result.recommendation.queue}</small>}
              <p className="run-status">{phaseLabels[result.status]}{result.incident_id && ` · ${result.incident_id}`}</p>
              {waiting && deadline !== null && (
                <p className="secondary">Подтвердить до {new Date(deadline).toLocaleTimeString('ru-RU')}</p>
              )}
              {waiting && (
                <p className="secondary">
                  Приоритет · {result.recommendation.priority}. Поля карточки · {result.recommendation.incident_fields.map(field => incidentFieldLabels[field]).join(', ')}
                </p>
              )}
              {result.publication && <PublishedFields publication={result.publication} />}
              {result.degradation && result.provider && (
                <p className="secondary">Ручной маршрут · {providerNames[result.provider] ?? result.provider}
                  {' · '}{result.degradation === 'model_timeout' ? 'таймаут' : 'модель недоступна'}
                </p>
              )}
              {result.error && <p className="notice">{result.error}</p>}
              {result.approval_block && (
                <p className="notice">
                  Последний отказ проверки · {result.approval_block.message}{' '}
                  <code>{result.approval_block.code}</code>
                </p>
              )}
              {onResolve && result.status === 'awaiting_approval' && (
                <div className="approval">
                  <button className="primary" disabled={resolving || busy} onClick={() => onResolve('approve')}>
                    {retryApproval ? 'Повторить регистрацию' : 'Зарегистрировать инцидент'}
                  </button>
                  <button className="outline" disabled={resolving || busy} onClick={() => onResolve('reject')}>
                    Отклонить
                  </button>
                </div>
              )}
              {canRun && isAgent && result.status === 'approval_expired' && (
                <button className="outline" disabled={busy || disabled} onClick={onRun}>
                  Запустить новый разбор
                </button>
              )}
              {onResolve && result.status === 'needs_review' && (
                <button className="primary" disabled={resolving || busy} onClick={() => onResolve('take_over')}>
                  Принять в ручной разбор
                </button>
              )}
              {onResolve && result.status === 'manual_handoff' && (
                <>
                  {result.manual_registration_available && onManual && (
                    <ManualIncidentForm key={result.id} verified={result.manual_evidence.length > 0}
                      busy={Boolean(resolving || busy)} onManual={onManual} />
                  )}
                  <div className="approval">
                    <button className={result.manual_registration_available ? 'outline' : 'primary'}
                      disabled={resolving || busy} onClick={() => onResolve('complete_manual')}>
                      {result.manual_registration_available ? 'Завершить без регистрации' : 'Завершить ручной разбор'}
                    </button>
                    <button className="outline" disabled={resolving || busy} onClick={() => onResolve('fail_manual')}>
                      Закрыть с ошибкой
                    </button>
                  </div>
                </>
              )}
              {resolutionError && <p className="notice" role="alert">{resolutionError}</p>}
            </section>
            {result.monitoring && <MonitoringDetails trace={result.monitoring} />}
            {result.coordination && (
              <details className="run-trace">
                <summary>Сообщения координации</summary>
                <CoordinationEvents trace={result.coordination} />
              </details>
            )}
            {result.delegation && (
              <details className="run-trace">
                <summary>Задания подчинённых агентов</summary>
                <DelegationEvents events={result.delegation.events} />
              </details>
            )}
            {(result.information.fields.length > 0 || result.flow_checks.some(check => check.blocked.length > 0)) && (
              <InformationFlow information={result.information} checks={result.flow_checks} />
            )}
            {result.manual_evidence.length > 0 && (
              <section className="boundary-results" aria-label="Источники ручного разбора">
                <h3>Источники ручного разбора</h3>
                <ul>{result.manual_evidence.map(step => (
                  <li key={step.action}>
                    <small>{step.observation.source} · {step.observation.observed_at}</small>
                    <strong>{step.label}</strong>
                    <p>{step.observation.summary}</p>
                  </li>
                ))}</ul>
              </section>
            )}
            <ShieldTrace checks={result.shield_checks} />
            <FilterTrace checks={result.filter_checks} />
            {result.support_card_available && canReadSupport && (
              <SupportCard key={result.id} runId={result.id} token={token} />
            )}
            {result.boundary_decisions.length > 0 && (
              <section className="boundary-results" aria-label="Решения защиты">
                <h3>Решения защиты</h3>
                <ul>
                  {result.boundary_decisions.map((decision, index) => (
                    <li key={index}>
                      <small>{threatNames[decision.threat]}</small>
                      <strong>{decision.title}</strong>
                      <p>{decision.detail}</p>
                    </li>
                  ))}
                </ul>
              </section>
            )}
            {isAgent && <Lifecycle key={result.id} events={result.lifecycle.events} />}
            <RunTrace key={result.id} runId={result.id} token={token} />
            <h3 className="history-title">Действия и наблюдения</h3>
            <ol className="history">
              {result.steps.map(step => (
                <li key={step.action}>
                  <strong>{step.label}</strong>
                  <p className="secondary">
                    <strong>{decisionSources[step.selected_by]}</strong>
                    {step.decision_provider && ` · ${providerNames[step.decision_provider] ?? step.decision_provider}`}
                    {' · '}{step.reason}
                  </p>
                  {step.executor_code === 'ok' && <small>Исполнитель вернул данные</small>}
                  {step.observation && (
                    <div className="observation">
                      <small>{step.observation.source} · {step.observation.observed_at}</small>
                      <p>{step.observation.summary}</p>
                    </div>
                  )}
                </li>
              ))}
            </ol>
          </>
        )}
      </div>
    </article>
  )
}

function Workspace({ token, identity, onLogout, course, changeArea }: {
  token: string; identity: Identity; onLogout: () => void; course: boolean; changeArea: (course: boolean) => void;
}) {
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [cases, setCases] = useState<WorkCase[]>([])
  const [loadingCases, setLoadingCases] = useState(!course)
  const [rulesOnly, setRulesOnly] = useState(false)
  const [threatCases, setThreatCases] = useState<ThreatCase[]>([])
  const [selectedThreat, setSelectedThreat] = useState<Threat>('prompt_injection')
  const [selectedId, setSelectedId] = useState('')
  const [model, setModel] = useState<ModelConfig>()
  const [fault, setFault] = useState<Fault | null>(null)
  const [recent, setRecent] = useState<RunSummary[]>([])
  const [historyError, setHistoryError] = useState('')
  const [resolving, setResolving] = useState(false)
  const [resolutionError, setResolutionError] = useState('')
  const [pendingApproval, setPendingApproval] = useState<PendingApproval>()
  const [loadError, setLoadError] = useState('')
  const [runs, setRuns] = useState<Partial<Record<Mode, Run>>>({})
  const [errors, setErrors] = useState<Partial<Record<Mode, string>>>({})
  const [busy, setBusy] = useState<Partial<Record<Mode, boolean>>>({})

  const canManage = identity.operator === 'duty_operator'
  const selectedCase = cases.find(item => item.id === selectedId)
  const waitingForAction = Boolean(busy.agent || busy.fixed || resolving)

  useEffect(() => {
    if (!course) {
      void request<WorkCase[]>('/api/cases', undefined, token).then(items => {
        setCases(items)
        setSelectedId(items[0]?.id ?? '')
      }).catch(error => setLoadError(error instanceof Error ? error.message : 'Не удалось загрузить обращения.'))
        .finally(() => setLoadingCases(false))
      void request<ModelConfig>('/api/model').then(config => {
        setModel(config)
        if (config.problem) setRulesOnly(true)
      }).catch(() => setRulesOnly(true))
      return
    }
    void Promise.all([
      request<Scenario[]>('/api/scenarios'),
      request<ModelConfig>('/api/model'),
      request<ThreatCase[]>('/api/threat-cases'),
    ])
      .then(([items, config, cases]) => {
        setScenarios(items)
        setSelectedId(items[0]?.id ?? '')
        setModel(config)
        setThreatCases(cases)
      })
      .catch(() => setLoadError('Не удалось загрузить стенд. Проверьте, что FastAPI запущен на порту 8000.'))
  }, [course, token])

  const scenario = scenarios.find(item => item.id === selectedId)
  const threatCase = threatCases.find(item => item.id === selectedThreat)
  const historyGroups = {
    'Ручная очередь': recent.filter(run => run.status === 'needs_review' || run.status === 'manual_handoff'),
    'Другие прогоны': recent.filter(run => run.status !== 'needs_review' && run.status !== 'manual_handoff'),
  }

  useEffect(() => {
    if (!selectedId) return
    const controller = new AbortController()
    void request<RunSummary[]>(`/api/runs?scenario_id=${encodeURIComponent(selectedId)}`, {
      signal: controller.signal,
    }, token).then(items => {
      if (!controller.signal.aborted) {
        setRecent(current => [...items, ...current.filter(item => !items.some(saved => saved.id === item.id))].slice(0, 30))
      }
    }).catch(() => {
      if (!controller.signal.aborted) setHistoryError('Не удалось загрузить историю прогонов.')
    })
    return () => controller.abort()
  }, [selectedId, token])

  function selectCase(id: string) {
    setSelectedId(id)
    setRuns({})
    setErrors({})
    setRecent([])
    setHistoryError('')
    setResolutionError('')
    setPendingApproval(undefined)
  }

  function rememberCase(item: WorkCase) {
    setCases(current => current.some(row => row.id === item.id)
      ? current.map(row => row.id === item.id ? item : row)
      : [item, ...current])
  }

  function remember(run: Run) {
    setRuns(current => ({ ...current, agent: run }))
    setRecent(current => {
      const saved = current.find(item => item.id === run.id)
      return [
        { id: run.id, status: run.status, started_at: saved?.started_at ?? run.lifecycle.events[0].at, threat: run.threat },
        ...current.filter(item => item.id !== run.id),
      ].slice(0, 30)
    })
  }

  async function openSaved(id: string) {
    setResolutionError('')
    if (!id) {
      setRuns(current => ({ ...current, agent: undefined }))
      return
    }
    setBusy(current => ({ ...current, agent: true }))
    setErrors(current => ({ ...current, agent: undefined }))
    try {
      setRuns(current => ({ ...current, agent: undefined }))
      const run = await request<Run>(`/api/runs/${id}`, undefined, token)
      remember(run)
    } catch (error) {
      setErrors(current => ({ ...current, agent: error instanceof Error ? error.message : 'Не удалось открыть прогон.' }))
    } finally {
      setBusy(current => ({ ...current, agent: false }))
    }
  }

  async function openRunInWorkbench(id: string) {
    await openSaved(id)
    document.getElementById('triage-runs')?.scrollIntoView({ block: 'start' })
  }

  async function resolve(decision: Decision) {
    const run = runs.agent
    if (!run) return
    setResolving(true)
    setResolutionError('')
    try {
      const path = `/api/runs/${run.id}`
      const headers: Record<string, string> = { 'Content-Type': 'application/json' }
      let body: { decision: Decision; transaction_token?: string } = { decision }
      if (decision === 'approve') {
        // После потери ответа повтор отправляет прежний токен и ключ идемпотентности.
        let grant = pendingApproval?.runId === run.id ? pendingApproval.grant : undefined
        if (!grant) {
          grant = await request<ApprovalGrant>(`${path}/approval-token`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ scenario_id: run.scenario_id, recommendation: run.recommendation }),
          }, token)
          setPendingApproval({ runId: run.id, grant })
        }
        headers['Idempotency-Key'] = grant.idempotency_key
        body = { decision, transaction_token: grant.token }
      }
      const updated = await request<Run>(`${path}/resolution`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      }, token)
      setPendingApproval(current => current?.runId === run.id ? undefined : current)
      remember(updated)
      if (!course) {
        void request<WorkCase>(`/api/cases/${run.scenario_id}`, undefined, token).then(rememberCase)
          .catch(() => setLoadError('Решение сохранено. Обновите список обращений, чтобы увидеть карточку инцидента.'))
      }
    } catch (error) {
      setResolutionError(error instanceof Error ? error.message : 'Не удалось сохранить решение.')
      if (error instanceof ApiError && error.status < 500) {
        setPendingApproval(current => current?.runId === run.id ? undefined : current)
      }
      if (error instanceof ApiError && error.code) {
        try {
          const current = await request<Run>(`/api/runs/${run.id}`, undefined, token)
          remember(current)
          if (current.approval_block?.code === error.code) setResolutionError('')
        } catch {
          // При сбое чтения остаётся доступно сообщение о первоначальном отказе.
        }
      }
    } finally {
      setResolving(false)
    }
  }

  async function prepareManual(priority?: 'P2') {
    const run = runs.agent
    if (!run) return
    const path = `/api/runs/${run.id}`
    setResolving(true)
    setResolutionError('')
    try {
      const updated = await request<Run>(`${path}/${priority ? 'manual-draft' : 'manual-evidence'}`, {
        method: 'POST',
        headers: priority ? { 'Content-Type': 'application/json' } : undefined,
        body: priority ? JSON.stringify({ priority }) : undefined,
      }, token)
      remember(updated)
    } catch (error) {
      setResolutionError(error instanceof Error ? error.message : 'Не удалось продолжить ручной разбор.')
      try {
        remember(await request<Run>(path, undefined, token))
      } catch {
        // При сбое чтения остаётся сообщение о первоначальной ошибке.
      }
    } finally {
      setResolving(false)
    }
  }

  async function refreshApproval() {
    const run = runs.agent
    if (!run) return
    try {
      const current = await request<Run>(`/api/runs/${run.id}`, undefined, token)
      setRuns(previous => previous.agent?.id === current.id ? { ...previous, agent: current } : previous)
      setRecent(previous => previous.map(item => item.id === current.id ? { ...item, status: current.status } : item))
    } catch (error) {
      setResolutionError(error instanceof Error ? error.message : 'Не удалось проверить срок согласования.')
    }
  }

  async function start(mode: Mode, options: {
    threat?: Threat; supportExport?: SupportExport; invalidOutput?: boolean
  } = {}) {
    const { threat, supportExport, invalidOutput } = options
    setBusy(current => ({ ...current, [mode]: true }))
    setRuns(current => ({ ...current, [mode]: undefined }))
    setErrors(current => ({ ...current, [mode]: undefined }))
    if (mode === 'agent') setResolutionError('')
    try {
      const result = await request<Run>(threat ? `/api/threat-cases/${threat}/runs` : '/api/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: threat ? undefined : JSON.stringify({
          scenario_id: selectedId,
          mode,
          fault: invalidOutput ? 'invalid_model_output' : mode === 'agent' && !supportExport ? fault : null,
          support_export: supportExport,
          rules_only: !course && rulesOnly,
        }),
      }, token)
      if (mode === 'agent') {
        remember(result)
        if (!course) setCases(current => current.map(item => item.id === result.scenario_id && item.revision === result.case_revision
          ? { ...item, analysis_status: result.status } : item))
      }
      else setRuns(current => ({ ...current, fixed: result }))
    } catch (error) {
      setErrors(current => ({
        ...current,
        [mode]: error instanceof Error ? error.message : 'Не удалось завершить разбор.',
      }))
    } finally {
      setBusy(current => ({ ...current, [mode]: false }))
    }
  }

  const runHistory = recent.length > 0 && (
    <div>
      <label htmlFor="saved-run">История разборов</label>
      <select id="saved-run" value={runs.agent?.id ?? ''} disabled={busy.agent || resolving}
        onChange={event => void openSaved(event.target.value)}>
        <option value="">Выберите прогон</option>
        {Object.entries(historyGroups).map(([label, items]) => items.length > 0 && (
          <optgroup key={label} label={label}>{items.map(run => (
            <option key={run.id} value={run.id}>
              {new Date(run.started_at).toLocaleString('ru-RU')} · {phaseLabels[run.status]}
              {run.threat && ` · ${threatNames[run.threat]}`}
            </option>
          ))}</optgroup>
        ))}
      </select>
    </div>
  )
  const currentRun = selectedCase && !selectedCase.closed_at &&
    (!runs.agent || runs.agent.case_revision === selectedCase.revision)
  const canResolveWork = Boolean(canManage && currentRun)
  const canLaunchWork = Boolean(canManage && selectedCase?.evidence && !selectedCase.closed_at)

  return (
    <>
      <header className="topbar">
        <div className="shell bar-content">
          <strong>Диспетчер ИТ-обращений</strong>
          <div className="account">
            {model && <span className="model">{providerNames[model.provider] ?? model.provider}</span>}
            <span>{identity.operator === 'duty_operator' ? 'Дежурный' : 'Наблюдатель'}</span>
            <button className="outline" onClick={onLogout}>Сменить пользователя</button>
          </div>
        </div>
      </header>
      <main className="shell">
        <nav className="workspace-nav" aria-label="Разделы кабинета">
          <button className={course ? 'outline' : 'primary'} aria-pressed={!course} disabled={waitingForAction}
            onClick={() => changeArea(false)}>Рабочие обращения</button>
          <button className={course ? 'primary' : 'outline'} aria-pressed={course} disabled={waitingForAction}
            onClick={() => changeArea(true)}>Учебные сценарии</button>
        </nav>
        <section className="intro">
          <h1>{course ? 'Учебные сценарии' : 'Рабочие обращения'}</h1>
          <p>{course ? 'Сравните маршруты и проследите цикл агента от наблюдения до результата действия.'
            : 'Диагностика задержек писем о заказах и регистрация инцидентов в очереди «Уведомления».'}</p>
        </section>
        {loadError && <p className="notice" role="alert">{loadError}</p>}
        {!course && <>
          {canManage && <CaseIntake token={token} disabled={waitingForAction || loadingCases}
            onCreated={item => { rememberCase(item); selectCase(item.id) }} />}
          <section className="case" aria-label="Очередь обращений">
            <h2>Очередь обращений</h2>
            <button className="outline" disabled={waitingForAction || loadingCases} onClick={() => {
              setLoadError('')
              setLoadingCases(true)
              void request<WorkCase[]>('/api/cases', undefined, token).then(items => {
                setCases(items)
                if (!selectedId) selectCase(items[0]?.id ?? '')
              }).catch(error => setLoadError(error instanceof Error ? error.message : 'Не удалось обновить список.'))
                .finally(() => setLoadingCases(false))
            }}>Обновить список</button>
            {cases.length === 0 ? <p className="secondary">{loadingCases ? 'Загружаем обращения…' : 'Очередь пуста.'}</p> : <div className="run-settings">
              <div>
                <label htmlFor="work-case">Обращение</label>
                <select id="work-case" value={selectedId} disabled={waitingForAction}
                  onChange={event => selectCase(event.target.value)}>
                  {cases.map(item => <option key={item.id} value={item.id}>
                    {item.id.slice(5, 13)} · {item.title} · {item.closed_at ? 'Закрыто' : item.incident?.id ??
                      (item.analysis_status ? phaseLabels[item.analysis_status] : item.evidence ? 'Готово к разбору' : 'Новое')}
                  </option>)}
                </select>
              </div>
              {runHistory}
              {historyError && <p className="notice">{historyError}</p>}
            </div>}
          </section>
          {selectedCase && <>
            <CaseDetails key={selectedCase.id} item={selectedCase} token={token} canManage={canManage}
              disabled={waitingForAction} onChange={rememberCase} />
            {selectedCase.incident && <section className="case" aria-label="Инцидент в трекере">
              <h2>{selectedCase.incident.id} · {selectedCase.incident.priority}</h2>
              <p>Очередь «Уведомления» · {new Date(selectedCase.incident.registered_at).toLocaleString('ru-RU')}</p>
              <button className="outline" disabled={waitingForAction}
                onClick={() => void openRunInWorkbench(selectedCase.incident!.run_id)}>Открыть запись трекера</button>
            </section>}
            {canLaunchWork && <section className="case">
              <label htmlFor="work-route">Маршрут диагностики</label>
              <select id="work-route" value={rulesOnly ? 'rules' : 'model'} disabled={waitingForAction}
                onChange={event => setRulesOnly(event.target.value === 'rules')}>
                <option value="rules">По регламенту</option>
                <option value="model" disabled={Boolean(model?.problem)}>С моделью</option>
              </select>
              {model?.problem && <p className="secondary">Для этого стенда доступен разбор по регламенту.</p>}
            </section>}
            {!currentRun && runs.agent?.status === 'awaiting_approval' && !selectedCase.closed_at && (
              <p className="notice">Данные изменились после разбора. Запустите его заново для согласования.</p>
            )}
            <section id="triage-runs" className="work-run" aria-label="Диагностика рабочего обращения">
              <RunPanel mode="agent" work result={runs.agent} busy={Boolean(busy.agent)} error={errors.agent}
                token={token} canRun={canLaunchWork} disabled={resolving || (!rulesOnly && Boolean(model?.problem))}
                resolving={resolving} resolutionError={resolutionError} canReadSupport={canManage}
                retryApproval={pendingApproval?.runId === runs.agent?.id && Boolean(pendingApproval)}
                onResolve={canResolveWork ? decision => void resolve(decision) : undefined}
                onManual={canResolveWork ? priority => void prepareManual(priority) : undefined}
                onRefresh={() => void refreshApproval()} onRun={() => void start('agent')} />
            </section>
            <AuditPanel key={`audit:${selectedCase.id}`} token={token} scenario={selectedCase.id} />
            <AnomalyPanel key={`anomalies:${selectedCase.id}`} token={token} scenario={selectedCase.id}
              revision={`${runs.agent?.id ?? ''}:${runs.agent?.status ?? ''}`} />
          </>}
          <MetricsPanel scope="work" token={token}
            revision={`${runs.agent?.id ?? ''}:${runs.agent?.status ?? ''}`} />
        </>}
        {scenario && (
          <>
            <section className="case">
              <label htmlFor="scenario">Обращение</label>
              <select
                id="scenario"
                value={selectedId}
                disabled={busy.agent || busy.fixed || resolving}
                onChange={event => selectCase(event.target.value)}
              >
                {scenarios.map(item => <option key={item.id} value={item.id}>{item.id} · {item.title}</option>)}
              </select>
              <p><strong>{scenario.received_at} · {scenario.source}</strong> · {scenario.report}</p>
              <p className="secondary"><strong>Цель</strong> · {scenario.goal}</p>
              <div className="run-settings">
                <div>
                  <label htmlFor="agent-fault">Условия агентного прогона</label>
                  <select id="agent-fault" value={fault ?? ''} disabled={busy.agent || resolving}
                    onChange={event => setFault((event.target.value || null) as Fault | null)}>
                    <option value="">Штатный прогон</option>
                    <option value="model_unavailable">Модель не отвечает после чтения очереди</option>
                    <option value="monitoring_timeout">Таймаут мониторинга</option>
                    <option value="stale_monitoring">Снимок устарел, жалобы продолжаются</option>
                    <option value="repeated_monitoring">Повторное чтение очереди</option>
                    <option value="oversized_observation">Ответ источника превышает лимит</option>
                  </select>
                </div>
                {runHistory}
                {historyError && <p className="notice">{historyError}</p>}
              </div>
            </section>
            {scenario.id === 'REQ-1842' && threatCase && (
              <section className="case threat-case" aria-label="Защитные сценарии">
                <h2>Основные угрозы</h2>
                <label htmlFor="threat-case">Проверка</label>
                <select id="threat-case" value={selectedThreat} disabled={busy.agent || resolving}
                  onChange={event => setSelectedThreat(event.target.value as Threat)}>
                  {threatCases.map(item => <option key={item.id} value={item.id}>{item.title}</option>)}
                </select>
                <p>{threatCase.situation}</p>
                <p className="secondary"><strong>Ожидаемый результат</strong> · {threatCase.expectation}</p>
                <button className="outline" disabled={busy.agent || resolving}
                  onClick={() => void start('agent', { threat: selectedThreat })}>Запустить проверку защиты</button>
              </section>
            )}
            {scenario.id === 'REQ-1842' && <OutcomeComparison token={token} />}
            {scenario.id === 'REQ-1842' && <FailClosedDemo token={token} />}
            {scenario.id === 'REQ-1842' && <ZeroTrustDemo token={token} />}
            {scenario.id === 'REQ-1842' && <PriorityHierarchyDemo token={token} />}
            {scenario.id === 'REQ-1842' && <RegistrationChecksDemo token={token} />}
            {scenario.id === 'REQ-1842' && <ApprovalTimeoutDemo token={token} />}
            {scenario.id === 'REQ-1842' && model && (
              <ServiceTokenDemo token={token} enabled={model.service_auth_mode === 'oauth'} />
            )}
            {scenario.id === 'REQ-1842' && model && (
              <AgentIdentityDemo token={token} enabled={['certificate', 'mtls_oauth'].includes(model.service_auth_mode)} tpm={model.tpm_enabled} />
            )}
            {scenario.id === 'REQ-1842' && model && (
              <InteragentDemo token={token} enabled={model.service_auth_mode === 'mtls_oauth'} />
            )}
            {scenario.id === 'REQ-1842' && <TransactionTokenDemo token={token} />}
            <AuditPanel key={scenario.id} token={token} scenario={scenario.id} />
            <MetricsPanel token={token}
              revision={`${runs.agent?.id ?? ''}:${runs.agent?.status ?? ''}:${runs.fixed?.id ?? ''}`} />
            <AnomalyPanel key={scenario.id} token={token} scenario={scenario.id}
              revision={`${runs.agent?.id ?? ''}:${runs.agent?.status ?? ''}:${runs.fixed?.id ?? ''}`} />
            {scenario.id === 'REQ-1842' && <ResiliencePanel token={token} />}
            {scenario.id === 'REQ-1842' && <ReliabilityPanel token={token} />}
            {scenario.id === 'REQ-1842' && <HealthPanel token={token} />}
            {scenario.id === 'REQ-1842' && <ForecastPanel token={token} canReplay={identity.operator === 'duty_operator'} />}
            {scenario.id === 'REQ-1842' && <CoordinationPanel token={token} known={recent}
              canOpen={!busy.agent && !resolving} onOpen={id => void openRunInWorkbench(id)} />}
            {scenario.id === 'REQ-1842' && <HierarchyPanel token={token} known={recent}
              canOpen={!busy.agent && !resolving} onOpen={id => void openRunInWorkbench(id)} />}
            {scenario.id === 'REQ-1842' && <ExfiltrationPanel token={token}
              canOpen={!busy.agent && !resolving} onOpen={id => void openRunInWorkbench(id)} />}
            {scenario.id === 'REQ-1842' && <SourceAccessPanel token={token} />}
            {scenario.id === 'REQ-1842' && (
              <SupportExportForm busy={Boolean(busy.agent || resolving)} modelReady={Boolean(model && !model.problem)}
                onRun={(supportExport, invalidOutput) => void start('agent', { supportExport, invalidOutput })} />
            )}
            {model?.problem && <p className="notice">{model.problem}</p>}
            <section id="triage-runs" className="comparison" aria-label="Сравнение режимов работы">
              {(['fixed', 'agent'] as const).map(mode => (
                <RunPanel key={mode} mode={mode} result={runs[mode]} error={errors[mode]}
                  token={token}
                  canReadSupport={identity.operator === 'duty_operator'}
                  busy={Boolean(busy[mode])}
                  disabled={mode === 'agent' && resolving}
                  resolving={resolving} resolutionError={mode === 'agent' ? resolutionError : undefined}
                  retryApproval={mode === 'agent' && pendingApproval?.runId === runs.agent?.id && Boolean(pendingApproval)}
                  onResolve={mode === 'agent' && identity.operator === 'duty_operator' ? decision => void resolve(decision) : undefined}
                  onManual={mode === 'agent' && identity.operator === 'duty_operator' ? priority => void prepareManual(priority) : undefined}
                  onRefresh={mode === 'agent' ? () => void refreshApproval() : undefined}
                  onRun={() => void start(mode)} />
              ))}
            </section>
          </>
        )}
      </main>
    </>
  )
}

function App() {
  const [key, setKey] = useState('')
  const [session, setSession] = useState<{ token: string; identity: Identity }>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [course, setCourse] = useState(false)

  async function connect() {
    const token = key.trim()
    setBusy(true)
    setError('')
    try {
      const identity = await request<Identity>('/api/identity', undefined, token)
      setSession({ token, identity })
      setKey('')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось подтвердить пользователя.')
    } finally {
      setBusy(false)
    }
  }

  if (session) return <Workspace key={course ? 'course' : 'work'} {...session} course={course}
    changeArea={setCourse} onLogout={() => { setSession(undefined); setCourse(false) }} />
  return (
    <main className="shell">
      <section className="intro">
        <h1>Диспетчер ИТ-обращений</h1>
        <p>Подключитесь с ключом дежурного или наблюдателя.</p>
      </section>
      <form className="case login" onSubmit={event => { event.preventDefault(); void connect() }}>
        <label htmlFor="operator-key">Ключ пользователя</label>
        <input id="operator-key" type="password" autoComplete="off" value={key}
          onChange={event => setKey(event.target.value)} required />
        <button className="primary" disabled={busy || !key.trim()}>
          {busy ? 'Проверяем ключ…' : 'Подключиться'}
        </button>
        {error && <p className="notice" role="alert">{error}</p>}
      </form>
    </main>
  )
}

createRoot(document.getElementById('root')!).render(<App />)
