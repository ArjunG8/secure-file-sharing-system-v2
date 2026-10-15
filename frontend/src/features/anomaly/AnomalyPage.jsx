// Owner: M7. Replace the TODO with the real UI for this module.
import ModulePage from '../../components/ModulePage.jsx'
import { detections } from './api.js'

const probes = [
  { label: 'GET /anomaly/detections', run: () => detections() },
]

export default function AnomalyPage() {
  return (
    <ModulePage
      code="M7"
      title="Anomaly detection"
      description="Isolation Forest model trained on audit-log features to flag unusual user behaviour."
      probes={probes}
    >
      <p className="rounded border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        TODO(M7): build this page.
      </p>
    </ModulePage>
  )
}
