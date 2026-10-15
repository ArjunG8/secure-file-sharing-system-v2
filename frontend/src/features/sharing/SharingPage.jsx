// Owner: M5. Replace the TODO with the real UI for this module.
import ModulePage from '../../components/ModulePage.jsx'
import { incomingShares, outgoingShares } from './api.js'

const probes = [
  { label: 'GET /shares/incoming', run: () => incomingShares() },
  { label: 'GET /shares/outgoing', run: () => outgoingShares() },
]

export default function SharingPage() {
  return (
    <ModulePage
      code="M5"
      title="Sharing & access control"
      description="Share files with other users (key re-wrapped per recipient), with expiry, download limits and revocation."
      probes={probes}
    >
      <p className="rounded border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        TODO(M5): build this page.
      </p>
    </ModulePage>
  )
}
