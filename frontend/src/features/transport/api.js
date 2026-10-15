// Owner: M10. Calls only this module's endpoints (see docs/api-contracts.md).
import { api } from '../../api/client.js'

export const transportStatus = () => api.get('/transport/status')
