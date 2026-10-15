// Owner: M4. Calls only this module's endpoints (see docs/api-contracts.md).
import { api } from '../../api/client.js'

export const getSignature = (fileId) => api.get(`/signatures/files/${fileId}`)
export const verifySignature = (fileId) => api.post(`/signatures/files/${fileId}/verify`)
