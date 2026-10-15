// Owner: M7. Calls only this module's endpoints (see docs/api-contracts.md).
import { api } from '../../api/client.js'

export const train = () => api.post('/anomaly/train', {})
export const score = () => api.post('/anomaly/score', {})
export const detections = () => api.get('/anomaly/detections')
