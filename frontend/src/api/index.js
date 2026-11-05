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
  alerts: (params) => http.get('/alerts', { params }),
  alert: (id) => http.get(`/alerts/${id}`),
  genericAlert: (data) => http.post('/alerts/generic', data),

  iocIps: (params) => http.get('/ioc/ips', { params }),
  iocIp: (id) => http.get(`/ioc/ips/${id}`),
  addIocIp: (data) => http.post('/ioc/ips', data),
  updateIocIp: (id, data) => http.put(`/ioc/ips/${id}`, data),
  deleteIocIp: (id) => http.delete(`/ioc/ips/${id}`),
  iocGeoCountries: () => http.get('/ioc/geo/countries'),
  iocDomains: (params) => http.get('/ioc/domains', { params }),
  iocDomain: (id) => http.get(`/ioc/domains/${id}`),
  addIocDomain: (data) => http.post('/ioc/domains', data),
  deleteIocDomain: (id) => http.delete(`/ioc/domains/${id}`),

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
}

export default api
