// Owner: M9. Calls only this module's endpoints (see docs/api-contracts.md).
import { api } from '../../api/client.js'

export const verifyFile = (fileId) => api.post(`/verification/files/${fileId}`)
export const verifyAuditChain = () => api.post('/verification/audit-chain')
export const listRuns = () => api.get('/verification/runs')
