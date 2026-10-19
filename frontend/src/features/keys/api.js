// Owner: M3. Calls only this module's endpoints (see docs/api-contracts.md).
import { api } from '../../api/client.js'

export const myKeys = () => api.get('/keys/me')
export const rotateKey = (purpose) => api.post('/keys/rotate', { purpose })
