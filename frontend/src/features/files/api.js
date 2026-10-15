// Owner: M2. Calls only this module's endpoints (see docs/api-contracts.md).
import { api } from '../../api/client.js'

export const listFiles = () => api.get('/files')
export function uploadFile(file) {
  const form = new FormData()
  form.append('file', file)
  return api.upload('/files', form)
}
export const downloadFile = (fileId) => api.get(`/files/${fileId}/download`)
export const deleteFile = (fileId) => api.delete(`/files/${fileId}`)
