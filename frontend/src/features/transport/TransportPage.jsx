// Owner: M10. Shows how this browser's requests actually reach the backend.
import { useEffect, useState } from 'react'
import { transportStatus } from './api.js'

function Row({ label, ok, value }) {
  return (
    <li className="flex items-center justify-between p-3 text-sm">
      <span>{label}</span>
      <span className={ok ? 'text-emerald-700' : 'text-amber-700'}>{value}</span>
    </li>
  )
}

export default function TransportPage() {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    transportStatus().then(setStatus).catch(setError)
  }, [])

  const pageIsHttps = window.location.protocol === 'https:'

  return (
    <section className="max-w-3xl space-y-6">
      <header>
        <p className="font-mono text-xs text-slate-500">M10</p>
        <h2 className="text-2xl font-semibold">Secure data transmission</h2>
        <p className="mt-2 text-slate-600">
          In production nginx terminates TLS 1.2/1.3 and the backend refuses plain HTTP. Local
          development runs over plain HTTP on localhost, which is expected there.
        </p>
      </header>
      {error && <p role="alert" className="text-sm text-red-700">{error.message}</p>}
      {status && (
        <ul className="divide-y divide-slate-200 rounded-lg border border-slate-200 bg-white">
          <Row label="This page loaded over" ok={pageIsHttps} value={pageIsHttps ? 'HTTPS' : 'HTTP'} />
          <Row label="Backend saw the request as" ok={status.scheme === 'https'} value={status.scheme.toUpperCase()} />
          <Row label="TLS version (reported by the proxy)" ok={Boolean(status.tls_version)} value={status.tls_version ?? 'none'} />
          <Row label="HSTS on responses" ok={status.hsts_enabled} value={status.hsts_enabled ? 'yes' : 'no'} />
          <Row label="Backend requires HTTPS" ok={status.https_enforced} value={status.https_enforced ? 'yes' : 'no (development)'} />
          <Row label="Behind the reverse proxy" ok={status.behind_proxy} value={status.behind_proxy ? 'yes' : 'no'} />
        </ul>
      )}
    </section>
  )
}
