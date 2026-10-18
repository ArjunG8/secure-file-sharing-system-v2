import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import KeysPage from './KeysPage.jsx'

const json = (status, body) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))

const key = (purpose, algorithm, id) => ({
  id, user_id: 'u1', purpose, algorithm, public_key_pem: '-----BEGIN PUBLIC KEY-----',
  fingerprint: `fp-${id}`, is_active: true, created_at: '2026-01-01',
})

describe('KeysPage', () => {
  it('lists public keys and rotates to ECC', async () => {
    let keys = [key('encryption', 'RSA-OAEP-3072-SHA256', 'k1'), key('signing', 'RSA-PSS-3072-SHA256', 'k2')]
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation((url, init = {}) => {
      if (url.endsWith('/keys/rotate')) {
        keys = [key('encryption', 'ECIES-X25519-HKDF-SHA256-AES256GCM', 'k3'), keys[1]]
        return json(200, keys[0])
      }
      return json(200, keys)
    })
    render(<KeysPage />)
    expect(await screen.findByText('RSA-OAEP-3072-SHA256')).toBeInTheDocument()
    await userEvent.click(screen.getAllByRole('button', { name: 'Rotate to ECC' })[0])
    expect(await screen.findByText('ECIES-X25519-HKDF-SHA256-AES256GCM')).toBeInTheDocument()
    const rotateCall = spy.mock.calls.find(([url]) => url.endsWith('/keys/rotate'))
    expect(JSON.parse(rotateCall[1].body)).toEqual({ purpose: 'encryption', algorithm: 'ecc' })
  })

  it('shows backend errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      json(401, { error: { code: 'unauthenticated', message: 'Not authenticated.' } }))
    render(<KeysPage />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Not authenticated.')
  })
})
