import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import TransportPage from './TransportPage.jsx'

const json = (status, body) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))

describe('TransportPage', () => {
  it('reports what the backend actually saw', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(200, {
      scheme: 'https', behind_proxy: true, hsts_enabled: true, https_enforced: true, tls_version: 'TLSv1.3',
    }))
    render(<TransportPage />)
    expect(await screen.findByText('TLSv1.3')).toBeInTheDocument()
    expect(screen.getByText('HTTPS', { selector: 'span.text-emerald-700' })).toBeInTheDocument()
  })

  it('labels development honestly', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(200, {
      scheme: 'http', behind_proxy: false, hsts_enabled: false, https_enforced: false, tls_version: null,
    }))
    render(<TransportPage />)
    expect(await screen.findByText('no (development)')).toBeInTheDocument()
  })
})
