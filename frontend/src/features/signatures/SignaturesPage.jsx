// Owner: M4. Replace the TODO with the real UI for this module.
import ModulePage from '../../components/ModulePage.jsx'
import { getSignature } from './api.js'

const probes = [
  { label: 'GET /signatures/files/:id', run: () => getSignature('00000000-0000-0000-0000-000000000000') },
]

export default function SignaturesPage() {
  return (
    <ModulePage
      code="M4"
      title="Digital signatures"
      description="RSA-PSS signatures over each file manifest, and on-demand signature verification."
      probes={probes}
    >
      <p className="rounded border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        TODO(M4): build this page.
      </p>
    </ModulePage>
  )
}
