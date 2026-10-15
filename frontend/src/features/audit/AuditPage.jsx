// Owner: M6. Replace the TODO with the real UI for this module.
import ModulePage from '../../components/ModulePage.jsx'
import { listLogs, verifyChain } from './api.js'

const probes = [
  { label: 'GET /audit/logs', run: () => listLogs() },
  { label: 'GET /audit/verify', run: () => verifyChain() },
]

export default function AuditPage() {
  return (
    <ModulePage
      code="M6"
      title="Audit log"
      description="Tamper-evident HMAC-SHA256 hash-chained log of every security event, with chain verification."
      probes={probes}
    >
      <p className="rounded border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        TODO(M6): build this page.
      </p>
    </ModulePage>
  )
}
