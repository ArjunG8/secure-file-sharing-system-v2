// Single HTTP layer for the whole frontend. Owned by the integration lead.
// Feature modules call `api.*` from their own features/<module>/api.js.

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1'

// Access token lives in memory only (never localStorage). Set by AuthContext (M1).
let accessToken = null

export function setAccessToken(token) {
  accessToken = token
}

export class ApiError extends Error {
  constructor(status, { code = 'http_error', message = 'Request failed', module = null, details = null } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.module = module
    this.details = details
  }

  get isNotImplemented() {
    return this.code === 'not_implemented'
  }
}

export async function apiRequest(path, { method = 'GET', body, formData, headers = {} } = {}) {
  const requestHeaders = { ...headers }
  if (accessToken) requestHeaders.Authorization = `Bearer ${accessToken}`

  let payload
  if (formData) {
    payload = formData
  } else if (body !== undefined) {
    requestHeaders['Content-Type'] = 'application/json'
    payload = JSON.stringify(body)
  }

  let response
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      method,
      headers: requestHeaders,
      body: payload,
      credentials: 'include',
    })
  } catch {
    throw new ApiError(0, { code: 'network_error', message: 'Cannot reach the backend.' })
  }

  if (response.status === 204) return null
  const contentType = response.headers.get('content-type') || ''

  if (!response.ok) {
    let error = { message: response.statusText || `HTTP ${response.status}` }
    if (contentType.includes('application/json')) {
      const data = await response.json().catch(() => null)
      if (data?.error) error = data.error
    }
    throw new ApiError(response.status, error)
  }

  if (contentType.includes('application/json')) return response.json()
  return response.blob()
}

export const api = {
  get: (path) => apiRequest(path),
  post: (path, body) => apiRequest(path, { method: 'POST', body }),
  delete: (path) => apiRequest(path, { method: 'DELETE' }),
  upload: (path, formData) => apiRequest(path, { method: 'POST', formData }),
}
