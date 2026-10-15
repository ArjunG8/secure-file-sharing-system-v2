// Owner: M6. Calls only this module's endpoints (see docs/api-contracts.md).
import { api } from '../../api/client.js'

export const listLogs = () => api.get('/audit/logs')
export const verifyChain = () => api.get('/audit/verify')
