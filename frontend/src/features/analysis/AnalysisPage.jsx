// Owner: M8. Replace the TODO with the real UI for this module.
import ModulePage from '../../components/ModulePage.jsx'
import { listAnalyses } from './api.js'

const probes = [
  { label: 'GET /analysis', run: () => listAnalyses() },
]

export default function AnalysisPage() {
  return (
    <ModulePage
      code="M8"
      title="AI security analysis"
      description="LLM summary of redacted security events and anomalies. Disabled unless an LLM provider is configured."
      probes={probes}
    >
      <p className="rounded border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        TODO(M8): build this page.
      </p>
    </ModulePage>
  )
}
