import axios from 'axios'
import { ElMessage } from 'element-plus'
import { logout, store } from '../store'

const http = axios.create({ baseURL: '/api/v1', timeout: 15000 })

http.interceptors.request.use((config) => {
  if (store.token) config.headers.Authorization = `Bearer ${store.token}`
  return config
})

http.interceptors.response.use(
  (response) => {
    if (response.config.responseType === 'blob') return response.data
    const body = response.data
    if (body && body.code !== 0) {
      ElMessage.error(body.msg || '请求失败')
      return Promise.reject(new Error(body.msg))
    }
    return body ? body.data : null
  },
  (error) => {
    const status = error.response?.status
    const msg = error.response?.data?.msg || error.message || '网络异常'
    if (status === 401) {
      logout()
      if (window.location.pathname !== '/login') window.location.assign('/login')
    } else {
      ElMessage.error(`${status || ''} ${msg}`)
    }
    return Promise.reject(error)
  },
)

export const api = {
  login: (data) => http.post('/auth/login', data),
  changePassword: (data) => http.post('/auth/password/change', data),
  me: () => http.get('/auth/me'),

  dashboard: () => http.get('/dashboard'),
  inspectionLatest: () => http.get('/inspections/latest'),
  inspectionRun: () => http.post('/inspections/run', null, { timeout: 90000 }),
  inspectionReports: (params) => http.get('/inspections/reports', { params }),
  inspectionReport: (id) => http.get(`/inspections/reports/${id}`),

  patrolRun: () => http.post('/patrols/run', null, { timeout: 120000 }),
  patrolLatest: () => http.get('/patrols/latest'),
  patrolRuns: (params) => http.get('/patrols', { params }),
  patrolRunDetail: (id) => http.get(`/patrols/${id}`),
  patrolMcpStatus: () => http.get('/patrols/mcp/status', { timeout: 60000 }),
  patrolConfig: () => http.get('/patrols/config'),
  patrolConfigSave: (data) => http.put('/patrols/config', data),
  patrolMcpTest: (data) => http.post('/patrols/mcp/test', data, { timeout: 60000 }),

  chatAsk: (data) => http.post('/chat/ask', data, { timeout: 120000 }),
  chatSessions: () => http.get('/chat/sessions'),
  chatSession: (id) => http.get(`/chat/sessions/${id}`),
  chatDeleteSession: (id) => http.delete(`/chat/sessions/${id}`),
  chatCatalog: () => http.get('/chat/catalog'),

  alerts: (params) => http.get('/alerts', { params }),
  alert: (id) => http.get(`/alerts/${id}`),
  genericAlert: (data) => http.post('/alerts/generic', data),

  iocIps: (params) => http.get('/ioc/ips', { params }),
  iocIp: (id) => http.get(`/ioc/ips/${id}`),
  addIocIp: (data) => http.post('/ioc/ips', data),
  updateIocIp: (id, data) => http.put(`/ioc/ips/${id}`, data),
  deleteIocIp: (id) => http.delete(`/ioc/ips/${id}`),
  exportIocIps: (params) => http.get('/ioc/ips/export', { params, responseType: 'blob' }),
  importIocIps: (formData) => http.post('/ioc/ips/import', formData, { timeout: 120000 }),
  iocDomains: (params) => http.get('/ioc/domains', { params }),
  iocDomain: (id) => http.get(`/ioc/domains/${id}`),
  addIocDomain: (data) => http.post('/ioc/domains', data),
  deleteIocDomain: (id) => http.delete(`/ioc/domains/${id}`),
  exportIocDomains: (params) => http.get('/ioc/domains/export', { params, responseType: 'blob' }),
  importIocDomains: (formData) => http.post('/ioc/domains/import', formData, { timeout: 120000 }),

  whitelist: (params) => http.get('/whitelist/ips', { params }),
  checkWhitelist: (ip) => http.get('/whitelist/ips/check', { params: { ip } }),
  addWhitelist: (data) => http.post('/whitelist/ips', data),
  importWhitelist: (text) => http.post('/whitelist/ips/import', { text }),
  deleteWhitelist: (id) => http.delete(`/whitelist/ips/${id}`),

  devices: (params) => http.get('/devices', { params }),
  addDevice: (data) => http.post('/devices', data),
  updateDevice: (id, data) => http.put(`/devices/${id}`, data),
  deleteDevice: (id) => http.delete(`/devices/${id}`),
  testDevice: (id) => http.post(`/devices/${id}/test`),
  plugins: () => http.get('/plugins'),
  testPlugin: (data) => http.post('/plugins/test', data),

  policies: (params) => http.get('/policies', { params }),
  policy: (id) => http.get(`/policies/${id}`),
  addPolicy: (data) => http.post('/policies', data),
  updatePolicy: (id, data) => http.put(`/policies/${id}`, data),
  togglePolicy: (id) => http.post(`/policies/${id}/toggle`),
  deletePolicy: (id) => http.delete(`/policies/${id}`),

  tasks: (params) => http.get('/tasks', { params }),
  task: (id) => http.get(`/tasks/${id}`),
  retryTask: (id) => http.post(`/tasks/${id}/retry`),
  cancelTask: (id) => http.post(`/tasks/${id}/cancel`),
  approveTask: (id, approve, reason) =>
    http.post(`/tasks/${id}/approve`, null, { params: { approve, reason } }),
  taskMetrics: () => http.get('/tasks/metrics/summary'),

  audit: (params) => http.get('/audit', { params }),
  systemStatus: () => http.get('/system/status'),
  getKillSwitch: () => http.get('/system/kill-switch'),
  setKillSwitch: (data) => http.post('/system/kill-switch', data),
  users: () => http.get('/system/users'),
  systemSettings: () => http.get('/system/settings'),
  saveSystemSettings: (data) => http.put('/system/settings', data),
}

export default api
