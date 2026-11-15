export type Publication = { affected_reports: number | null; technical_evidence: string | null }

export function PublishedFields({ publication }: { publication: Publication }) {
  return (
    <div className="publication">
      <strong>Записано в трекер</strong>
      {publication.affected_reports !== null && <p>Обращений: {publication.affected_reports}</p>}
      {publication.technical_evidence && <p>{publication.technical_evidence}</p>}
    </div>
  )
}
