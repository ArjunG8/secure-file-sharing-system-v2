import { useEffect, useState } from 'react'
import { api } from '../../api/client.js'

// Honest project dashboard: shows exactly what GET /api/v1/modules reports.
export default function ModuleStatusPage() {
  const [modules, setModules] = useState(null)
  const [health, setHealth] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    Promise.all([api.get('/modules'), api.get('/health')])
      .then(([m, h]) => {
        setModules(m)
        setHealth(h)
      })
      .catch(setError)
  }, [])

  return (
    <section className="max-w-3xl space-y-4">
      <h2 className="text-2xl font-semibold">Module status</h2>
      {error && (
        <p role="alert" className="text-red-700">
          Backend unavailable: {error.message}
        </p>
      )}
      {health && (
        <p className="text-sm text-slate-600">
          API v{health.version} · database {health.database}
        </p>
      )}
      {modules && (
        <ul className="divide-y divide-slate-200 rounded-lg border border-slate-200 bg-white">
          {modules.map((m) => (
            <li key={m.code} className="flex items-center justify-between gap-4 p-3">
              <span>
                <span className="mr-2 font-mono text-xs text-slate-500">{m.code}</span>
                {m.name}
              </span>
              <span
                className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${
                  m.implemented ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'
                }`}
              >
                {m.implemented ? 'Implemented' : 'Not implemented'}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
