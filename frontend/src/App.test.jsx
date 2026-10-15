import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import App from './App.jsx'
import { AuthProvider } from './context/AuthContext.jsx'
import { MODULE_ROUTES } from './routes.jsx'

const MODULES = Array.from({ length: 10 }, (_, i) => ({
  number: i + 1,
  code: `M${i + 1}`,
  key: `m${i + 1}`,
  name: `Module ${i + 1}`,
  implemented: i === 0,
}))

function mockBackend() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((url) => {
    const json = (status, body) =>
      Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))
    if (url.endsWith('/modules')) return json(200, MODULES)
    if (url.endsWith('/health')) return json(200, { status: 'ok', version: '0.1.0', database: 'ok' })
    return json(501, { error: { code: 'not_implemented', message: 'Not built yet', module: 'M2' } })
  })
}

function renderAt(path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('App', () => {
  it('has a navigation entry for all ten modules', () => {
    mockBackend()
    renderAt('/')
    expect(MODULE_ROUTES).toHaveLength(10)
    const nav = screen.getByRole('navigation', { name: 'Modules' })
    for (const r of MODULE_ROUTES) expect(nav).toHaveTextContent(r.label)
  })

  it('shows the real implementation status reported by the backend', async () => {
    mockBackend()
    renderAt('/')
    expect(await screen.findByText('Module 1')).toBeInTheDocument()
    expect(screen.getAllByText('Implemented')).toHaveLength(1)
    expect(screen.getAllByText('Not implemented')).toHaveLength(9)
  })

  it('surfaces an honest 501 from an unimplemented module', async () => {
    mockBackend()
    renderAt('/files')
    await userEvent.click(screen.getByRole('button', { name: 'GET /files' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('HTTP 501 · not_implemented')
  })
})
