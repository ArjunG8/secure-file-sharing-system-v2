// Route table: one page per module. Owned by the integration lead; each module
// owner only edits files inside their own features/<module>/ folder.
import AuthPage from './features/auth/AuthPage.jsx'
import FilesPage from './features/files/FilesPage.jsx'
import KeysPage from './features/keys/KeysPage.jsx'
import SignaturesPage from './features/signatures/SignaturesPage.jsx'
import SharingPage from './features/sharing/SharingPage.jsx'
import AuditPage from './features/audit/AuditPage.jsx'
import AnomalyPage from './features/anomaly/AnomalyPage.jsx'
import AnalysisPage from './features/analysis/AnalysisPage.jsx'
import VerificationPage from './features/verification/VerificationPage.jsx'
import TransportPage from './features/transport/TransportPage.jsx'

export const MODULE_ROUTES = [
  { code: 'M1', path: '/account', label: 'Account', Component: AuthPage },
  { code: 'M2', path: '/files', label: 'Files', Component: FilesPage },
  { code: 'M3', path: '/keys', label: 'Keys', Component: KeysPage },
  { code: 'M4', path: '/signatures', label: 'Signatures', Component: SignaturesPage },
  { code: 'M5', path: '/sharing', label: 'Sharing', Component: SharingPage },
  { code: 'M6', path: '/audit', label: 'Audit log', Component: AuditPage },
  { code: 'M7', path: '/anomalies', label: 'Anomalies', Component: AnomalyPage },
  { code: 'M8', path: '/analysis', label: 'AI analysis', Component: AnalysisPage },
  { code: 'M9', path: '/verification', label: 'Verification', Component: VerificationPage },
  { code: 'M10', path: '/transport', label: 'Transport', Component: TransportPage },
]
