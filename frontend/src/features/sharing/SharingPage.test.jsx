import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SharingPage from './SharingPage.jsx'

const json = (status, body) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))

const SHARE = {
  id: 'g1', file_id: 'f1', file_name: 'plan.pdf', grantee_id: 'u2', grantee_email: 'bob@example.com',
  granted_by_id: 'u1', permission: 'read', expires_at: null, revoked_at: null, max_downloads: 3,
  download_count: 1, created_at: '2026-01-01', active: true,
}
const page = (items) => ({ items, total: items.length, limit: 50, offset: 0 })

describe('SharingPage', () => {
  it('creates a share with a download limit and lists it', async () => {
    let outgoing = []
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation((url, init = {}) => {
      if (init.method === 'POST') {
        outgoing = [SHARE]
        return json(201, SHARE)
      }
      return json(200, page(url.endsWith('/outgoing') ? outgoing : []))
    })
    render(<SharingPage />)
    await userEvent.type(screen.getByLabelText('File id'), 'f1')
    await userEvent.type(screen.getByLabelText('Recipient email'), 'bob@example.com')
    await userEvent.type(screen.getByLabelText(/Max downloads/), '3')
    await userEvent.click(screen.getByRole('button', { name: 'Share' }))
    expect(await screen.findByText('plan.pdf')).toBeInTheDocument()
    const body = JSON.parse(spy.mock.calls.find(([, i]) => i?.method === 'POST')[1].body)
    expect(body).toEqual({ file_id: 'f1', recipient_email: 'bob@example.com', max_downloads: 3 })
  })

  it('revokes a share', async () => {
    let share = SHARE
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation((url, init = {}) => {
      if (init.method === 'DELETE') {
        share = { ...SHARE, revoked_at: '2026-01-02', active: false }
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      return json(200, page(url.endsWith('/outgoing') ? [share] : []))
    })
    render(<SharingPage />)
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke' }))
    expect(await screen.findByText('revoked')).toBeInTheDocument()
    expect(spy.mock.calls.some(([url, i]) => i?.method === 'DELETE' && url.endsWith('/shares/g1'))).toBe(true)
  })
})
