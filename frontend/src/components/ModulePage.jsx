import { useState } from 'react'

// Shared scaffold for a module page. `probes` call real backend endpoints and show the
// actual response - including honest 501 "not implemented" errors - never fake data.
export default function ModulePage({ code, title, description, probes = [], children }) {
  const [results, setResults] = useState({})

  async function runProbe(probe) {
    setResults((r) => ({ ...r, [probe.label]: { state: 'loading' } }))
    try {
      const data = await probe.run()
      setResults((r) => ({ ...r, [probe.label]: { state: 'ok', data } }))
    } catch (error) {
      setResults((r) => ({ ...r, [probe.label]: { state: 'error', error } }))
    }
  }

  return (
    <section className="max-w-3xl space-y-6">
      <header>
        <p className="font-mono text-xs text-slate-500">{code}</p>
        <h2 className="text-2xl font-semibold">{title}</h2>
        <p className="mt-2 text-slate-600">{description}</p>
      </header>

      {children}

      {probes.length > 0 && (
        <div className="rounded-lg border border-slate-200 bg-white p-4">
          <h3 className="mb-3 font-medium">Backend endpoints</h3>
          <ul className="space-y-3">
            {probes.map((probe) => {
              const result = results[probe.label]
              return (
                <li key={probe.label} className="space-y-1">
                  <button
                    type="button"
                    onClick={() => runProbe(probe)}
                    className="rounded bg-slate-900 px-3 py-1.5 text-sm text-white hover:bg-slate-700"
                  >
                    {probe.label}
                  </button>
                  {result?.state === 'loading' && <p className="text-sm text-slate-500">Calling…</p>}
                  {result?.state === 'ok' && (
                    <pre className="overflow-x-auto rounded bg-slate-100 p-2 text-xs">
                      {JSON.stringify(result.data, null, 2)}
                    </pre>
                  )}
                  {result?.state === 'error' && (
                    <p role="alert" className={`text-sm ${result.error.isNotImplemented ? 'text-amber-700' : 'text-red-700'}`}>
                      {result.error.status ? `HTTP ${result.error.status} · ` : ''}
                      {result.error.code}: {result.error.message}
                    </p>
                  )}
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </section>
  )
}
