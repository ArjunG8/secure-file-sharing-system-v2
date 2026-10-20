import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import AnalysisPage from './AnalysisPage.jsx'

const json = (status, body) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))

const ANALYSIS = {
  id: 'a1', status: 'completed', provider: 'fake', model: 'fake-rules-v1', summary: 'Analyzed 7 events.',
  findings: [{ severity: 'high', title: 'Repeated failed logins', evidence_event_ids: [1, 2], recommendation: 'Check sources.' }],
  created_at: '2026-01-01', completed_at: '2026-01-01',
}

describe('AnalysisPage', () => {
  it('runs an analysis and shows findings with evidence', async () => {
    let items = []
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation((url, init = {}) => {
      if (init.method === 'POST') {
        items = [ANALYSIS]
        return json(201, ANALYSIS)
      }
      return json(200, { items, total: items.length, limit: 50, offset: 0 })
    })
    render(<AnalysisPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Run analysis' }))
    expect(await screen.findByText('Repeated failed logins')).toBeInTheDocument()
    expect(screen.getByText('audit events: 1, 2')).toBeInTheDocument()
    const body = JSON.parse(spy.mock.calls.find(([, i]) => i?.method === 'POST')[1].body)
    expect(new Date(body.until) - new Date(body.since)).toBe(24 * 3600 * 1000)
  })

  it('explains when analysis is disabled', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((url, init = {}) => init.method === 'POST'
      ? json(503, { error: { code: 'service_unavailable', message: 'LLM analysis is disabled (set LLM_PROVIDER to enable it).' } })
      : json(200, { items: [], total: 0, limit: 50, offset: 0 }))
    render(<AnalysisPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Run analysis' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('disabled')
  })
})
