// Owner: M5. Share your files, see what is shared with you, revoke shares.
// The backend enforces every permission; this page only reflects what it reports.
import { useCallback, useEffect, useState } from 'react'
import { createShare, incomingShares, outgoingShares, revokeShare } from './api.js'

const input = 'rounded border border-slate-300 px-2 py-1 text-sm'
const button = 'rounded bg-slate-900 px-3 py-1.5 text-sm text-white hover:bg-slate-700 disabled:opacity-50'

function Status({ share }) {
  const label = share.revoked_at ? 'revoked' : share.active ? 'active' : 'inactive'
  const style = share.active ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-100 text-slate-600'
  return <span className={`rounded px-2 py-0.5 text-xs ${style}`}>{label}</span>
}

function ShareList({ title, page, onRevoke, who }) {
  if (!page) return null
  return (
    <div className="rounded-lg border border-slate-200 bg-white">
      <h3 className="border-b border-slate-200 p-3 font-medium">{title} ({page.total})</h3>
      <ul className="divide-y divide-slate-100">
        {page.items.map((s) => (
          <li key={s.id} className="flex flex-wrap items-center justify-between gap-2 p-3 text-sm">
            <span>
              <span className="font-medium">{s.file_name}</span>
              <span className="ml-2 text-xs text-slate-500">
                {who(s)} · downloads {s.download_count}{s.max_downloads ? `/${s.max_downloads}` : ''}
                {s.expires_at ? ` · expires ${s.expires_at}` : ''}
              </span>
            </span>
            <span className="flex items-center gap-2">
              <Status share={s} />
              {onRevoke && !s.revoked_at && (
                <button className="rounded border border-slate-300 px-2 py-1 text-xs" onClick={() => onRevoke(s.id)}>
                  Revoke
                </button>
              )}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function SharingPage() {
  const [form, setForm] = useState({ file_id: '', recipient_email: '', max_downloads: '', expires_at: '' })
  const [outgoing, setOutgoing] = useState(null)
  const [incoming, setIncoming] = useState(null)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)

  const load = useCallback(() => Promise.all([outgoingShares(), incomingShares()])
    .then(([o, i]) => { setOutgoing(o); setIncoming(i) })
    .catch(setError), [])

  useEffect(() => {
    load()
  }, [load])

  async function run(action, success) {
    setError(null)
    setNotice(null)
    try {
      await action()
      setNotice(success)
      await load()
    } catch (e) {
      setError(e)
    }
  }

  function submit(e) {
    e.preventDefault()
    const body = { file_id: form.file_id.trim(), recipient_email: form.recipient_email.trim() }
    if (form.max_downloads) body.max_downloads = Number(form.max_downloads)
    if (form.expires_at) body.expires_at = new Date(form.expires_at).toISOString()
    run(() => createShare(body), `Shared with ${body.recipient_email}`)
  }

  const bind = (name) => ({ value: form[name], onChange: (e) => setForm((f) => ({ ...f, [name]: e.target.value })) })

  return (
    <section className="max-w-4xl space-y-6">
      <header>
        <p className="font-mono text-xs text-slate-500">M5</p>
        <h2 className="text-2xl font-semibold">Sharing & access control</h2>
        <p className="mt-2 text-slate-600">
          Sharing re-wraps the file key for the recipient. Access is denied by default and ends when a
          share is revoked, expires or reaches its download limit.
        </p>
      </header>
      <form onSubmit={submit} className="grid gap-3 rounded-lg border border-slate-200 bg-white p-4 md:grid-cols-2">
        <label className="text-sm">File id<input className={`${input} mt-1 block w-full font-mono`} required {...bind('file_id')} /></label>
        <label className="text-sm">Recipient email<input type="email" className={`${input} mt-1 block w-full`} required {...bind('recipient_email')} /></label>
        <label className="text-sm">Max downloads (optional)<input type="number" min="1" max="1000" className={`${input} mt-1 block w-full`} {...bind('max_downloads')} /></label>
        <label className="text-sm">Expires (optional)<input type="datetime-local" className={`${input} mt-1 block w-full`} {...bind('expires_at')} /></label>
        <div><button className={button}>Share</button></div>
      </form>
      {error && <p role="alert" className="text-sm text-red-700">{error.message}</p>}
      {notice && <p role="status" className="text-sm text-emerald-700">{notice}</p>}
      <ShareList title="Shared by me" page={outgoing} who={(s) => s.grantee_email}
        onRevoke={(id) => run(() => revokeShare(id), 'Share revoked')} />
      <ShareList title="Shared with me" page={incoming} who={() => 'shared with you'} />
    </section>
  )
}
