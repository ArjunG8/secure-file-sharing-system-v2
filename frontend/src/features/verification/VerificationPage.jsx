// Owner: M9. Re-verify a stored file or the audit chain and see each check's result.
import { useState } from 'react'
import { listRuns, verifyAuditChain, verifyFile } from './api.js'

const button = 'rounded bg-slate-900 px-3 py-1.5 text-sm text-white hover:bg-slate-700 disabled:opacity-50'

function Report({ report }) {
  return (
    <div role="status" className="rounded-lg border border-slate-200 bg-white p-4 text-sm">
      <p className={`font-medium ${report.passed ? 'text-emerald-700' : 'text-red-700'}`}>
        {report.target_type === 'file' ? 'File' : 'Audit chain'} {report.passed ? 'verified' : 'FAILED verification'}
      </p>
      <ul className="mt-2 space-y-1">
        {report.checks.map((c) => (
          <li key={c.name} className={c.passed ? 'text-emerald-700' : 'text-red-700'}>
            {c.passed ? '✓' : '✗'} <span className="font-mono">{c.name}</span>
            {c.detail && <span className="ml-2 text-xs text-slate-600">{c.detail}</span>}
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function VerificationPage() {
  const [fileId, setFileId] = useState('')
  const [report, setReport] = useState(null)
  const [runs, setRuns] = useState(null)
  const [error, setError] = useState(null)

  async function run(action) {
    setError(null)
    try {
      await action()
    } catch (e) {
      setError(e)
    }
  }

  return (
    <section className="max-w-3xl space-y-6">
      <header>
        <p className="font-mono text-xs text-slate-500">M9</p>
        <h2 className="text-2xl font-semibold">Cryptographic verification</h2>
        <p className="mt-2 text-slate-600">
          Re-checks a file's stored ciphertext hash, owner signature, key unwrapping, GCM tag and
          plaintext hash without downloading it, or verifies the whole audit hash chain (admin).
        </p>
      </header>
      <div className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          File id
          <input className="ml-2 w-80 rounded border border-slate-300 px-2 py-1 font-mono text-xs"
            value={fileId} onChange={(e) => setFileId(e.target.value.trim())} />
        </label>
        <button className={button} disabled={!fileId}
          onClick={() => run(async () => setReport(await verifyFile(fileId)))}>Verify file</button>
        <button className={button} onClick={() => run(async () => setReport(await verifyAuditChain()))}>
          Verify audit chain
        </button>
        <button className={button} onClick={() => run(async () => setRuns(await listRuns()))}>History</button>
      </div>
      {error && <p role="alert" className="text-sm text-red-700">{error.message}</p>}
      {report && <Report report={report} />}
      {runs && (
        <ul className="divide-y divide-slate-200 rounded-lg border border-slate-200 bg-white text-sm">
          {runs.items.map((r) => (
            <li key={r.id} className="flex justify-between p-2">
              <span>{r.created_at} · {r.target_type} {r.target_id ?? ''}</span>
              <span className={r.passed ? 'text-emerald-700' : 'text-red-700'}>{r.passed ? 'passed' : 'failed'}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
