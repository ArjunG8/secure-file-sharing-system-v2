// Owner: M1. Replace the TODO with the real UI for this module.
import ModulePage from '../../components/ModulePage.jsx'
import { me } from './api.js'

const probes = [
  { label: 'GET /auth/me', run: () => me() },
]

export default function AuthPage() {
  return (
    <ModulePage
      code="M1"
      title="Account & authentication"
      description="Registration and login with Argon2id password hashing, JWT access tokens and HttpOnly refresh cookies."
      probes={probes}
    >
      <p className="rounded border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        TODO(M1): build this page.
      </p>
    </ModulePage>
  )
}
