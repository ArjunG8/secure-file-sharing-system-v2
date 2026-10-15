import { describe, expect, it, vi } from 'vitest'
import { ApiError, api, setAccessToken } from './client.js'

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('api client', () => {
  it('returns parsed JSON on success', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(200, { status: 'ok' }))
    await expect(api.get('/health')).resolves.toEqual({ status: 'ok' })
    expect(fetch).toHaveBeenCalledWith('/api/v1/health', expect.objectContaining({ method: 'GET' }))
  })

  it('turns the backend error envelope into an ApiError', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse(501, {
        error: { code: 'not_implemented', message: 'Not built yet', module: 'M2', details: null },
      }),
    )
    const error = await api.get('/files').catch((e) => e)
    expect(error).toBeInstanceOf(ApiError)
    expect(error.status).toBe(501)
    expect(error.module).toBe('M2')
    expect(error.isNotImplemented).toBe(true)
  })

  it('reports network failures without crashing', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'))
    const error = await api.get('/health').catch((e) => e)
    expect(error.code).toBe('network_error')
  })

  it('sends the bearer token only when one is set', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(jsonResponse(200, {})))
    setAccessToken('test-token')
    await api.get('/auth/me')
    expect(spy.mock.calls[0][1].headers.Authorization).toBe('Bearer test-token')
    setAccessToken(null)
    await api.get('/auth/me')
    expect(spy.mock.calls[1][1].headers.Authorization).toBeUndefined()
  })
})
