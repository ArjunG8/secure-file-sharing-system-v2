// Owner: M3. Shows your active public keys and lets you rotate them.
import { useCallback, useEffect, useState } from 'react'
import { myKeys, rotateKey } from './api.js'

const button = 'rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100 disabled:opacity-50'

export default function KeysPage() {
  const [keys, setKeys] = useState([])
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    setError(null)
    return myKeys().then(setKeys).catch(setError)
  }, [])

  useEffect(() => {
    load()
  }, [load])

  async function rotate(purpose, algorithm) {
    setBusy(true)
    setError(null)
    try {
      await rotateKey(purpose, algorithm)
      await load()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="max-w-3xl space-y-6">
      <header>
        <p className="font-mono text-xs text-slate-500">M3</p>
        <h2 className="text-2xl font-semibold">Key management</h2>
        <p className="mt-2 text-slate-600">
          Your public keys. Private keys never leave the server and are stored encrypted under the
          master key. Rotation keeps old keys so existing files stay readable.
        </p>
      </header>
      {error && <p role="alert" className="text-sm text-red-700">{error.message}</p>}
      <ul className="space-y-3">
        {keys.map((k) => (
          <li key={k.id} className="space-y-2 rounded-lg border border-slate-200 bg-white p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-medium capitalize">{k.purpose} key</span>
              <span className="rounded bg-slate-100 px-2 py-0.5 font-mono text-xs">{k.algorithm}</span>
            </div>
            <p className="break-all font-mono text-xs text-slate-600">SHA-256 fingerprint: {k.fingerprint}</p>
            <div className="flex flex-wrap gap-2">
              <button className={button} disabled={busy} onClick={() => rotate(k.purpose)}>
                Rotate
              </button>
              <button className={button} disabled={busy} onClick={() => rotate(k.purpose, 'rsa')}>
                Rotate to RSA-3072
              </button>
              <button className={button} disabled={busy} onClick={() => rotate(k.purpose, 'ecc')}>
                Rotate to ECC
              </button>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}
