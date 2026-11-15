const levels = {
  policy: 'Политика',
  heuristics: 'Эвристики',
  judge: 'LLM-судья',
  hitl: 'Решение дежурного',
}

export type ShieldCheck = { level: keyof typeof levels; code: string; detail: string }

export function ShieldTrace({ checks }: { checks: ShieldCheck[] }) {
  if (!checks.length) return null
  return (
    <section className="boundary-results" aria-label="Решения Shield Pipeline">
      <h3>Shield Pipeline</h3>
      <ul>
        {checks.map((check, index) => (
          <li key={index} data-level={check.level}>
            <small>{levels[check.level]}</small>
            <strong><code>{check.code}</code></strong>
            <p>{check.detail}</p>
          </li>
        ))}
      </ul>
    </section>
  )
}
