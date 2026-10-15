// Owner: M8. Calls only this module's endpoints (see docs/api-contracts.md).
import { api } from '../../api/client.js'

export const runAnalysis = (data) => api.post('/analysis', data)
export const listAnalyses = () => api.get('/analysis')
