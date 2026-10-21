import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SignaturesPage from './SignaturesPage.jsx'

const json = (status, body) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))

describe('SignaturesPage', () => {
  it('shows authorship and integrity separately', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(200, {
      file_id: 'f1', valid: false, signature_valid: true, ciphertext_intact: false,
      checked_at: '2026-01-01', reason: 'stored ciphertext does not match the signed ciphertext hash',
    }))
    render(<SignaturesPage />)
    await userEvent.type(screen.getByLabelText('File id'), 'f1')
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }))
    const status = await screen.findByRole('status')
    expect(status).toHaveTextContent('Verification FAILED')
    expect(status).toHaveTextContent('✓ Signature by the file owner')
    expect(status).toHaveTextContent('✗ Stored ciphertext matches')
  })

  it('shows the signed manifest', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(200, {
      file_id: 'f1', algorithm: 'Ed25519', signature_b64: 'c2ln', signing_key_id: 'k1', signer_id: 'u1',
      manifest: { v: 1, file_id: 'f1', original_filename: 'report.pdf' },
    }))
    render(<SignaturesPage />)
    await userEvent.type(screen.getByLabelText('File id'), 'f1')
    await userEvent.click(screen.getByRole('button', { name: 'Show signature' }))
    expect(await screen.findByText(/report.pdf/)).toBeInTheDocument()
  })
})
