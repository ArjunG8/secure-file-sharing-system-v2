// Owner: M3. Replace the TODO with the real UI for this module.
import ModulePage from '../../components/ModulePage.jsx'
import { myKeys } from './api.js'

const probes = [
  { label: 'GET /keys/me', run: () => myKeys() },
]

export default function KeysPage() {
  return (
    <ModulePage
      code="M3"
      title="Key management"
      description="Your RSA-3072 encryption (OAEP) and signing (PSS) public keys, fingerprints and rotation."
      probes={probes}
    >
      <p className="rounded border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        TODO(M3): build this page.
      </p>
    </ModulePage>
  )
}
