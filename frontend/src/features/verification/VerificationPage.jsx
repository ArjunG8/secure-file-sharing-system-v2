// Owner: M9. Replace the TODO with the real UI for this module.
import ModulePage from '../../components/ModulePage.jsx'
import { listRuns } from './api.js'

const probes = [
  { label: 'GET /verification/runs', run: () => listRuns() },
]

export default function VerificationPage() {
  return (
    <ModulePage
      code="M9"
      title="Cryptographic verification"
      description="Re-check a file's GCM tag, hashes and signature, and verify the audit chain end-to-end."
      probes={probes}
    >
      <p className="rounded border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        TODO(M9): build this page.
      </p>
    </ModulePage>
  )
}
