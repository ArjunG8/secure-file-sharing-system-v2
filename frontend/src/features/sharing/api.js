// Owner: M5. Calls only this module's endpoints (see docs/api-contracts.md).
import { api } from '../../api/client.js'

export const createShare = (data) => api.post('/shares', data)
export const incomingShares = () => api.get('/shares/incoming')
export const outgoingShares = () => api.get('/shares/outgoing')
export const revokeShare = (grantId) => api.delete(`/shares/${grantId}`)
