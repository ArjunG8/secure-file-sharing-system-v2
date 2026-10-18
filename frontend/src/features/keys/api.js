// Owner: M3. Calls only this module's endpoints (see docs/api-contracts.md).
import { api } from '../../api/client.js'

export const myKeys = () => api.get('/keys/me')
// algorithm: 'rsa' | 'ecc' | undefined (keep the current family)
export const rotateKey = (purpose, algorithm) =>
  api.post('/keys/rotate', algorithm ? { purpose, algorithm } : { purpose })
export const userPublicKeys = (userId) => api.get(`/keys/users/${userId}/public`)
