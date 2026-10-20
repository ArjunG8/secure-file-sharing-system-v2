// Owner: M2. Upload (encrypted server-side with AES-256-GCM), list, download, delete.
import { useCallback, useEffect, useState } from 'react'
import { deleteFile, downloadFile, listFiles, uploadFile } from './api.js'

const button = 'rounded bg-slate-900 px-3 py-1.5 text-sm text-white hover:bg-slate-700 disabled:opacity-50'
const ghost = 'rounded border border-slate-300 px-2 py-1 text-xs hover:bg-slate-100'

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export default function FilesPage() {
  const [files, setFiles] = useState(null)
  const [selected, setSelected] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)

  const load = useCallback(() => listFiles().then((page) => setFiles(page.items)).catch(setError), [])

  useEffect(() => {
    load()
  }, [load])

  async function run(action, success) {
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      await action()
      if (success) setNotice(success)
      await load()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="max-w-4xl space-y-6">
      <header>
        <p className="font-mono text-xs text-slate-500">M2</p>
        <h2 className="text-2xl font-semibold">Encrypted files</h2>
        <p className="mt-2 text-slate-600">
          Files are encrypted with AES-256-GCM under a fresh key before storage. Downloads are
          decrypted only after the ciphertext hash, signature and GCM tag all verify.
        </p>
      </header>

      <form className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-200 bg-white p-4"
        onSubmit={(e) => {
          e.preventDefault()
          if (selected) run(() => uploadFile(selected), `Uploaded ${selected.name}`)
        }}>
        <label className="text-sm">
          File
          <input type="file" className="ml-2 text-sm" onChange={(e) => setSelected(e.target.files[0] ?? null)} />
        </label>
        <button className={button} disabled={!selected || busy}>Upload</button>
      </form>

      {error && (
        <p role="alert" className="text-sm text-red-700">
          {error.message}{error.code === 'integrity_failure' ? ' (integrity check failed)' : ''}
        </p>
      )}
      {notice && <p role="status" className="text-sm text-emerald-700">{notice}</p>}

      {files && (
        <ul className="divide-y divide-slate-200 rounded-lg border border-slate-200 bg-white">
          {files.length === 0 && <li className="p-3 text-sm text-slate-500">No files yet.</li>}
          {files.map((f) => (
            <li key={f.id} className="flex flex-wrap items-center justify-between gap-2 p-3 text-sm">
              <span>
                <span className="font-medium">{f.original_filename}</span>
                <span className="ml-2 text-xs text-slate-500">{formatSize(f.size_bytes)} · {f.permission}</span>
              </span>
              <span className="flex gap-2">
                <button className={ghost} disabled={busy}
                  onClick={() => run(async () => saveBlob(await downloadFile(f.id), f.original_filename))}>
                  Download
                </button>
                {f.permission === 'owner' && (
                  <button className={ghost} disabled={busy}
                    onClick={() => run(() => deleteFile(f.id), `Deleted ${f.original_filename}`)}>
                    Delete
                  </button>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
