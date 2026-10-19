// Owner: M2. Replace the TODO with the real UI for this module.
import ModulePage from '../../components/ModulePage.jsx'
import { listFiles } from './api.js'

const probes = [
  { label: 'GET /files', run: () => listFiles() },
]

export default function FilesPage() {
  return (
    <ModulePage
      code="M2"
      title="Encrypted files"
      description="Upload files that are encrypted with AES-256-GCM before storage; download decrypts after integrity checks."
      probes={probes}
    >
      <p className="rounded border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        TODO(M2): build this page.
      </p>
    </ModulePage>
  )
}
