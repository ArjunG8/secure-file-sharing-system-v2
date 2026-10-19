// Owner: M8. Run an AI review of recent redacted security events; read past analyses.
// Results are advisory text only - they never change any permission or decision.
import { useCallback, useEffect, useState } from 'react'
import { listAnalyses, runAnalysis } from './api.js'

const button = 'rounded bg-slate-900 px-3 py-1.5 text-sm text-white hover:bg-slate-700 disabled:opacity-50'
const severityStyle = {
  low: 'bg-slate-100 text-slate-700', medium: 'bg-amber-100 text-amber-800',
  high: 'bg-red-100 text-red-800', critical: 'bg-red-600 text-white',
}

function Analysis({ a }) {
  return (
    <li className="space-y-2 rounded-lg border border-slate-200 bg-white p-4 text-sm">
      <p className="text-xs text-slate-500">
        {a.created_at} · {a.provider}/{a.model} · <span className={a.status === 'completed' ? 'text-emerald-700' : 'text-red-700'}>{a.status}</span>
      </p>
      <p>{a.summary}</p>
      <ul className="space-y-2">
        {a.findings.map((f, i) => (
          <li key={i} className="rounded border border-slate-100 p-2">
            <span className={`mr-2 rounded px-2 py-0.5 text-xs ${severityStyle[f.severity]}`}>{f.severity}</span>
            <strong>{f.title}</strong>
            <p className="mt-1 text-slate-600">{f.recommendation}</p>
            {f.evidence_event_ids.length > 0 && (
              <p className="mt-1 font-mono text-xs text-slate-500">audit events: {f.evidence_event_ids.join(', ')}</p>
            )}
          </li>
        ))}
      </ul>
    </li>
  )
}

export default function AnalysisPage() {
  const [hours, setHours] = useState(24)
  const [page, setPage] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const load = useCallback(() => listAnalyses().then(setPage).catch(setError), [])

  useEffect(() => {
    load()
  }, [load])

  async function run() {
    setBusy(true)
    setError(null)
    const until = new Date()
    const since = new Date(until.getTime() - hours * 3600 * 1000)
    try {
      await runAnalysis({ since: since.toISOString(), until: until.toISOString(), include_anomalies: true })
      await load()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="max-w-4xl space-y-6">
      <header>
        <p className="font-mono text-xs text-slate-500">M8</p>
        <h2 className="text-2xl font-semibold">AI security analysis</h2>
        <p className="mt-2 text-slate-600">
          Audit events are redacted (pseudonymous ids, truncated IPs, no user agents) before an LLM
          summarises them. Its output is advisory and never changes access or verification decisions.
        </p>
      </header>
      <div className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          Last
          <input type="number" min="1" max="720" className="mx-2 w-20 rounded border border-slate-300 px-2 py-1 text-sm"
            value={hours} onChange={(e) => setHours(Number(e.target.value) || 1)} />
          hours
        </label>
        <button className={button} disabled={busy} onClick={run}>{busy ? 'Analysing…' : 'Run analysis'}</button>
      </div>
      {error && <p role="alert" className="text-sm text-red-700">{error.message}</p>}
      {page && <ul className="space-y-3">{page.items.map((a) => <Analysis key={a.id} a={a} />)}</ul>}
    </section>
  )
}
