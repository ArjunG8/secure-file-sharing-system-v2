import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import FilesPage from './FilesPage.jsx'

const json = (status, body) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))

const FILE = {
  id: 'f1', owner_id: 'u1', original_filename: 'report.txt', content_type: 'text/plain', size_bytes: 2048,
  encryption_algorithm: 'AES-256-GCM', plaintext_sha256: 'x', signature_algorithm: 'RSA-PSS-SHA256',
  permission: 'owner', created_at: '2026-01-01',
}

describe('FilesPage', () => {
  it('uploads a file as multipart and refreshes the list', async () => {
    let items = []
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation((url, init = {}) => {
      if (init.method === 'POST') {
        items = [FILE]
        return json(201, FILE)
      }
      return json(200, { items, total: items.length, limit: 50, offset: 0 })
    })
    render(<FilesPage />)
    expect(await screen.findByText('No files yet.')).toBeInTheDocument()
    await userEvent.upload(screen.getByLabelText('File'), new File(['hello'], 'report.txt', { type: 'text/plain' }))
    await userEvent.click(screen.getByRole('button', { name: 'Upload' }))
    expect(await screen.findByText('report.txt')).toBeInTheDocument()
    const post = spy.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(post[1].body).toBeInstanceOf(FormData)
  })

  it('downloads through a blob URL', async () => {
    URL.createObjectURL = vi.fn(() => 'blob:mock')
    URL.revokeObjectURL = vi.fn()
    vi.spyOn(globalThis, 'fetch').mockImplementation((url) => {
      if (url.endsWith('/download')) {
        return Promise.resolve(new Response('secret bytes', { status: 200, headers: { 'Content-Type': 'application/octet-stream' } }))
      }
      return json(200, { items: [FILE], total: 1, limit: 50, offset: 0 })
    })
    render(<FilesPage />)
    await userEvent.click(await screen.findByRole('button', { name: 'Download' }))
    expect(URL.createObjectURL).toHaveBeenCalled()
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:mock')
  })

  it('reports integrity failures', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((url) => {
      if (url.endsWith('/download')) {
        return json(502, { error: { code: 'integrity_failure', message: 'The file failed an integrity check and was not returned.' } })
      }
      return json(200, { items: [FILE], total: 1, limit: 50, offset: 0 })
    })
    render(<FilesPage />)
    await userEvent.click(await screen.findByRole('button', { name: 'Download' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('integrity check failed')
  })
})
