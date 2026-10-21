// Owner: M4. Inspect a file's signed manifest and verify authorship + integrity.
import { useState } from 'react'
import { getSignature, verifySignature } from './api.js'

const button = 'rounded bg-slate-900 px-3 py-1.5 text-sm text-white hover:bg-slate-700 disabled:opacity-50'

function Check({ ok, label }) {
  return (
    <li className={ok ? 'text-emerald-700' : 'text-red-700'}>
      {ok ? '✓' : '✗'} {label}
    </li>
  )
}

export default function SignaturesPage() {
  const [fileId, setFileId] = useState('')
  const [signature, setSignature] = useState(null)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  async function run(action) {
    setError(null)
    try {
      await action()
    } catch (e) {
      setError(e)
    }
  }

  return (
    <section className="max-w-3xl space-y-6">
      <header>
        <p className="font-mono text-xs text-slate-500">M4</p>
        <h2 className="text-2xl font-semibold">Digital signatures & file integrity</h2>
        <p className="mt-2 text-slate-600">
          Each upload's manifest is signed with the owner's RSA-PSS or Ed25519 key. A valid
          signature proves who vouched for the file; matching hashes alone only prove it is unchanged.
        </p>
      </header>
      <div className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          File id
          <input className="ml-2 w-80 rounded border border-slate-300 px-2 py-1 font-mono text-xs"
            value={fileId} onChange={(e) => setFileId(e.target.value.trim())} />
        </label>
        <button className={button} disabled={!fileId}
          onClick={() => run(async () => setSignature(await getSignature(fileId)))}>Show signature</button>
        <button className={button} disabled={!fileId}
          onClick={() => run(async () => setResult(await verifySignature(fileId)))}>Verify</button>
      </div>
      {error && <p role="alert" className="text-sm text-red-700">{error.message}</p>}
      {result && (
        <div role="status" className="rounded-lg border border-slate-200 bg-white p-4 text-sm">
          <p className="font-medium">{result.valid ? 'Verified' : 'Verification FAILED'}</p>
          <ul className="mt-2 space-y-1">
            <Check ok={result.signature_valid} label="Signature by the file owner (authorship)" />
            <Check ok={result.ciphertext_intact} label="Stored ciphertext matches the signed hash (integrity)" />
          </ul>
          {result.reason && <p className="mt-2 text-xs text-slate-600">{result.reason}</p>}
        </div>
      )}
      {signature && (
        <div className="space-y-2 rounded-lg border border-slate-200 bg-white p-4 text-sm">
          <p>Algorithm: <span className="font-mono">{signature.algorithm}</span></p>
          <p className="break-all font-mono text-xs">Signature: {signature.signature_b64}</p>
          <pre className="overflow-x-auto rounded bg-slate-100 p-2 text-xs">{JSON.stringify(signature.manifest, null, 2)}</pre>
        </div>
      )}
    </section>
  )
}
