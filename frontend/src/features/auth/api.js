// Owner: M1. Calls only this module's endpoints (see docs/api-contracts.md).
import { api, apiRequest, csrfHeaders } from '../../api/client.js'

export const register = (data) => api.post('/auth/register', data)
export const login = (data) => api.post('/auth/login', data)
export const me = () => api.get('/auth/me')
export const logout = () => api.post('/auth/logout')
export const changePassword = (data) => api.post('/auth/change-password', data)
export const refresh = () =>
  apiRequest('/auth/refresh', { method: 'POST', headers: csrfHeaders(), retryOnUnauthorized: false })
