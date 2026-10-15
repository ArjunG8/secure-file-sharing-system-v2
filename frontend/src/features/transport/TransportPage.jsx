// Owner: M10. Replace the TODO with the real UI for this module.
import ModulePage from '../../components/ModulePage.jsx'
import { transportStatus } from './api.js'

const probes = [
  { label: 'GET /transport/status', run: () => transportStatus() },
]

export default function TransportPage() {
  return (
    <ModulePage
      code="M10"
      title="Transport security"
      description="HTTPS/TLS termination, HSTS and security headers. Shows how this request reached the server."
      probes={probes}
    >
      <p className="rounded border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        TODO(M10): build this page.
      </p>
    </ModulePage>
  )
}
