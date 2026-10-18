import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AuthProvider } from '../../context/AuthContext.jsx'
import AuthPage from './AuthPage.jsx'

const json = (status, body) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))

const USER = { id: 'u1', email: 'alice@example.com', username: 'alice', role: 'user', created_at: '2026-01-01' }

function mockBackend({ loginOk = true } = {}) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((url, init = {}) => {
    if (url.endsWith('/auth/refresh')) return json(401, { error: { code: 'unauthenticated', message: 'no session' } })
    if (url.endsWith('/auth/login')) {
      return loginOk
        ? json(200, { access_token: 'tok-1', token_type: 'bearer', expires_in: 900 })
        : json(401, { error: { code: 'unauthenticated', message: 'Invalid email or password.' } })
    }
    if (url.endsWith('/auth/me')) {
      return init.headers?.Authorization === 'Bearer tok-1' ? json(200, USER) : json(401, { error: {} })
    }
    if (url.endsWith('/auth/logout')) return Promise.resolve(new Response(null, { status: 204 }))
    return json(404, { error: { code: 'not_found', message: 'nope' } })
  })
}

async function signIn(password = 'correct horse battery staple') {
  await userEvent.type(screen.getAllByLabelText('Email')[0], 'alice@example.com')
  await userEvent.type(screen.getAllByLabelText('Password')[0], password)
  await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
}

describe('AuthPage', () => {
  it('signs in with the bearer token and shows the account', async () => {
    const fetchSpy = mockBackend()
    render(<AuthProvider><AuthPage /></AuthProvider>)
    await signIn()
    expect(await screen.findByText(/Signed in as/)).toHaveTextContent('alice')
    const loginCall = fetchSpy.mock.calls.find(([url]) => url.endsWith('/auth/login'))
    expect(loginCall[1].credentials).toBe('include') // refresh cookie can be set
  })

  it('shows the generic error for bad credentials', async () => {
    mockBackend({ loginOk: false })
    render(<AuthProvider><AuthPage /></AuthProvider>)
    await signIn('wrong')
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password.')
  })

  it('signs out and forgets the token', async () => {
    const fetchSpy = mockBackend()
    render(<AuthProvider><AuthPage /></AuthProvider>)
    await signIn()
    await userEvent.click(await screen.findByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument()
    const logoutCall = fetchSpy.mock.calls.find(([url]) => url.endsWith('/auth/logout'))
    expect(logoutCall[1].headers.Authorization).toBe('Bearer tok-1')
  })
})
