import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import VerificationPage from './VerificationPage.jsx'

const json = (status, body) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))

describe('VerificationPage', () => {
  it('shows every check of a failed file verification', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(200, {
      id: 'r1', target_type: 'file', target_id: 'f1', passed: false, created_at: '2026-01-01',
      checks: [
        { name: 'ciphertext_sha256', passed: false, detail: 'stored blob does not match the recorded hash' },
        { name: 'signature', passed: true, detail: null },
        { name: 'gcm_tag', passed: false, detail: 'authentication tag mismatch' },
      ],
    }))
    render(<VerificationPage />)
    await userEvent.type(screen.getByLabelText('File id'), 'f1')
    await userEvent.click(screen.getByRole('button', { name: 'Verify file' }))
    const status = await screen.findByRole('status')
    expect(status).toHaveTextContent('FAILED verification')
    expect(status).toHaveTextContent('✗ gcm_tag')
    expect(status).toHaveTextContent('✓ signature')
  })

  it('reports permission errors for the audit chain', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      json(403, { error: { code: 'forbidden', message: 'Administrator role required.' } }))
    render(<VerificationPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Verify audit chain' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Administrator role required.')
  })
})
