// Owner: M1. Sign in, register, change password, sign out.
import { useState } from 'react'
import { useAuth } from '../../context/AuthContext.jsx'
import * as authApi from './api.js'

const input = 'mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm'
const button = 'rounded bg-slate-900 px-4 py-2 text-sm text-white hover:bg-slate-700 disabled:opacity-50'

function useForm(initial) {
  const [values, setValues] = useState(initial)
  const bind = (name) => ({
    name,
    value: values[name],
    onChange: (e) => setValues((v) => ({ ...v, [name]: e.target.value })),
  })
  return [values, bind, () => setValues(initial)]
}

function Field({ label, ...props }) {
  return (
    <label className="block text-sm">
      {label}
      <input className={input} required {...props} />
    </label>
  )
}

function Message({ error, success }) {
  if (error) return <p role="alert" className="text-sm text-red-700">{error.message}</p>
  if (success) return <p role="status" className="text-sm text-emerald-700">{success}</p>
  return null
}

function useSubmit(action) {
  const [state, setState] = useState({ busy: false, error: null, success: null })
  const submit = async (e) => {
    e.preventDefault()
    setState({ busy: true, error: null, success: null })
    try {
      const success = await action()
      setState({ busy: false, error: null, success })
    } catch (error) {
      setState({ busy: false, error, success: null })
    }
  }
  return [state, submit]
}

function SignInForm() {
  const { signIn } = useAuth()
  const [values, bind] = useForm({ email: '', password: '' })
  const [state, submit] = useSubmit(() => signIn(values.email, values.password).then(() => null))
  return (
    <form onSubmit={submit} className="space-y-3 rounded-lg border border-slate-200 bg-white p-4">
      <h3 className="font-medium">Sign in</h3>
      <Field label="Email" type="email" autoComplete="username" {...bind('email')} />
      <Field label="Password" type="password" autoComplete="current-password" {...bind('password')} />
      <button className={button} disabled={state.busy}>Sign in</button>
      <Message {...state} />
    </form>
  )
}

function RegisterForm() {
  const [values, bind, reset] = useForm({ email: '', username: '', password: '' })
  const [state, submit] = useSubmit(async () => {
    await authApi.register(values)
    reset()
    return 'Account created. You can sign in now.'
  })
  return (
    <form onSubmit={submit} className="space-y-3 rounded-lg border border-slate-200 bg-white p-4">
      <h3 className="font-medium">Create an account</h3>
      <Field label="Email" type="email" autoComplete="email" {...bind('email')} />
      <Field label="Username" autoComplete="username" minLength={3} maxLength={64} {...bind('username')} />
      <Field label="Password (at least 12 characters)" type="password" autoComplete="new-password"
        minLength={12} maxLength={128} {...bind('password')} />
      <button className={button} disabled={state.busy}>Register</button>
      <Message {...state} />
    </form>
  )
}

function ChangePasswordForm() {
  const { clearSession } = useAuth()
  const [values, bind] = useForm({ current_password: '', new_password: '' })
  const [state, submit] = useSubmit(async () => {
    await authApi.changePassword(values)
    clearSession() // the backend ended every session
    return null
  })
  return (
    <form onSubmit={submit} className="space-y-3 rounded-lg border border-slate-200 bg-white p-4">
      <h3 className="font-medium">Change password</h3>
      <Field label="Current password" type="password" autoComplete="current-password"
        {...bind('current_password')} />
      <Field label="New password" type="password" autoComplete="new-password" minLength={12}
        maxLength={128} {...bind('new_password')} />
      <button className={button} disabled={state.busy}>Change password</button>
      <Message {...state} />
    </form>
  )
}

export default function AuthPage() {
  const { user, signOut } = useAuth()
  return (
    <section className="max-w-3xl space-y-6">
      <header>
        <p className="font-mono text-xs text-slate-500">M1</p>
        <h2 className="text-2xl font-semibold">Account & authentication</h2>
        <p className="mt-2 text-slate-600">
          Argon2id password hashing, short-lived access tokens kept in memory, and an HttpOnly
          refresh cookie protected by a CSRF token.
        </p>
      </header>
      {user ? (
        <>
          <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-white p-4">
            <p className="text-sm">
              Signed in as <strong>{user.username}</strong> ({user.email}) · role {user.role}
            </p>
            <button className={button} onClick={() => signOut()}>Sign out</button>
          </div>
          <ChangePasswordForm />
        </>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          <SignInForm />
          <RegisterForm />
        </div>
      )}
    </section>
  )
}
