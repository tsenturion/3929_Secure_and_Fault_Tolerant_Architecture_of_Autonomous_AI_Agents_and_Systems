type Level = 'shared' | 'duty_only'
type Key = 'queue_size' | 'oldest_minutes' | 'channel' | 'message_ids' | 'runbook_id'
type Party = 'monitoring' | 'catalog' | 'diagnostic' | 'runbook' | 'master' | 'triage' | 'model' | 'duty' | 'observer'
type Field = { key: Key; level: Level; value: number | string | string[] }
export type FlowData = { fields: Field[] }
export type FlowCheck = { source: Party; destination: Party; passed: Key[]; blocked: Key[] }

const levels: Record<Level, string> = { shared: 'Общие данные', duty_only: 'Только для дежурного' }
const fields: Record<Key, string> = {
  queue_size: 'Размер очереди',
  oldest_minutes: 'Возраст старейшего сообщения',
  channel: 'Затронутый канал',
  message_ids: 'Внутренние идентификаторы сообщений',
  runbook_id: 'Опубликованный регламент',
}
const parties: Record<Party, string> = {
  monitoring: 'Мониторинг', catalog: 'Каталог', diagnostic: 'Агент диагностики',
  runbook: 'Агент регламентов', master: 'Master Agent', triage: 'Агент разбора',
  model: 'Модель', duty: 'Дежурный', observer: 'Наблюдатель',
}
const channels: Record<string, string> = { email: 'Электронная почта', push: 'Push', sms: 'SMS' }
const number = new Intl.NumberFormat('ru-RU')

function FieldValue({ field }: { field: Field }) {
  if (Array.isArray(field.value)) {
    return <ul>{field.value.map(value => <li key={value}><code>{value}</code></li>)}</ul>
  }
  if (typeof field.value === 'number') {
    return <>{number.format(field.value)}{field.key === 'oldest_minutes' && ' мин'}</>
  }
  return <>{field.key === 'channel' ? channels[field.value] ?? field.value : field.value}</>
}

export function InformationFlow({ information, checks }: { information: FlowData; checks: FlowCheck[] }) {
  return (
    <details className="run-trace" aria-label="Контроль информационных потоков">
      <summary>Контроль информационных потоков (IFC)</summary>
      <div className="metrics-table">
        <table>
          <thead><tr><th scope="col">Поле</th><th scope="col">Доступ</th><th scope="col">Значение</th></tr></thead>
          <tbody>{information.fields.map(field => (
            <tr key={field.key}>
              <th scope="row">{fields[field.key]}</th>
              <td>{levels[field.level]}</td>
              <td><FieldValue field={field} /></td>
            </tr>
          ))}</tbody>
        </table>
        <table>
          <caption>Проверки передачи между участниками</caption>
          <thead><tr><th scope="col">Маршрут</th><th scope="col">Разрешено</th><th scope="col">Скрыто</th></tr></thead>
          <tbody>{checks.map((check, index) => (
            <tr key={index}>
              <th scope="row">{parties[check.source]} → {parties[check.destination]}</th>
              <td>{check.passed.map(key => fields[key]).join(', ') || '—'}</td>
              <td>{check.blocked.map(key => fields[key]).join(', ') || '—'}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </details>
  )
}
