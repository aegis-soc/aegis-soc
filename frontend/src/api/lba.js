// LBA（登录行为分析）API 层。
// 契约见 docs/lba-api.md——mock 与真实接口共用同一套响应结构，切真实接口组件零改动。
// Mock 开关：DEV 且未显式 VITE_LBA_MOCK=false 时启用；生产构建永远走真实接口。
import { http } from './index'

export const LBA_MOCK = import.meta.env.DEV && import.meta.env.VITE_LBA_MOCK !== 'false'

// ---------------------------------------------------------------------------
// mock 数据（示例数据，非实际统计；口径见 docs/lba-design.md 第 11 节）
// ---------------------------------------------------------------------------

const DAY = 86400000
const now = () => Date.now()
const ago = (ms) => now() - ms
const fmt = (ts) => {
  const d = new Date(ts)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

const APPS = [
  { id: 'app-finance', url: '/api/report/list' },
  { id: 'app-oa', url: '/api/flow/approve' },
  { id: 'app-crm', url: '/api/customer/detail' },
  { id: 'app-wiki', url: '/pages/index' },
]

const DEVICES = {
  zhangsan: [
    { ua_class: 'pc', browser: 'chrome', browser_ver: '120', managed: 'unknown',
      ua_raw: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36' },
  ],
  lisi: [
    { ua_class: 'feishu', browser: 'feishu', browser_ver: '7.0', managed: 'managed',
      ua_raw: 'Mozilla/5.0 (Linux; Android 14) LvmiFeishu/7.0.10 Chrome/108.0.0.0' },
    { ua_class: 'pc', browser: 'edge', browser_ver: '119', managed: 'unknown',
      ua_raw: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0' },
  ],
  wangwu: [
    { ua_class: 'pc', browser: 'chrome', browser_ver: '121', managed: 'unknown',
      ua_raw: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/121.0.0.0 Safari/537.36' },
    { ua_class: 'mobile', browser: 'safari', browser_ver: '17', managed: 'unknown',
      ua_raw: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1' },
    { ua_class: 'feishu', browser: 'feishu', browser_ver: '7.0', managed: 'managed',
      ua_raw: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) LvmiFeishu/7.0.10' },
  ],
  zhaoliu: [
    { ua_class: 'mobile', browser: 'chrome', browser_ver: '119', managed: 'unknown',
      ua_raw: 'Mozilla/5.0 (Linux; Android 13; M2102K1C) AppleWebKit/537.36 Chrome/119.0.0.0 Mobile Safari/537.36' },
  ],
}

const IPS = {
  zhangsan: [
    { ip: '61.144.101.23', country: '中国', city: '广东省·深圳市', isp: '电信' },
    { ip: '61.144.108.77', country: '中国', city: '广东省·深圳市', isp: '电信' },
    { ip: '113.98.55.10', country: '中国', city: '广东省·深圳市', isp: '联通' },
  ],
  lisi: [
    { ip: '112.10.33.201', country: '中国', city: '浙江省·杭州市', isp: '移动' },
    { ip: '183.129.244.16', country: '中国', city: '浙江省·杭州市', isp: '电信' },
    { ip: '45.125.33.100', country: '俄罗斯', city: '莫斯科', isp: 'MTS' },
    { ip: '185.220.101.5', country: '德国', city: '法兰克福', isp: 'Netcup' },
  ],
  wangwu: [
    { ip: '119.97.180.66', country: '中国', city: '湖北省·武汉市', isp: '电信' },
    { ip: '119.97.181.90', country: '中国', city: '湖北省·宜昌市', isp: '电信' },
  ],
  zhaoliu: [
    { ip: '219.136.77.41', country: '中国', city: '广东省·广州市', isp: '移动' },
    { ip: '219.136.78.88', country: '中国', city: '广东省·广州市', isp: '移动' },
  ],
}

const USERS = [
  { username: 'zhangsan', risk: 'low', device_count: 1, device_types: ['pc'], ip_count_7d: 3, country_count_7d: 1, pending_events: 0, last_active: ago(5 * 60000) },
  { username: 'lisi', risk: 'high', device_count: 2, device_types: ['feishu', 'pc'], ip_count_7d: 4, country_count_7d: 2, pending_events: 3, last_active: ago(11 * 60000) },
  { username: 'wangwu', risk: 'medium', device_count: 3, device_types: ['pc', 'mobile', 'feishu'], ip_count_7d: 2, country_count_7d: 1, pending_events: 1, last_active: ago(38 * 60000) },
  { username: 'zhaoliu', risk: 'low', device_count: 1, device_types: ['mobile'], ip_count_7d: 2, country_count_7d: 1, pending_events: 0, last_active: ago(2 * 3600000) },
]

function mockTimeline(username) {
  const dev = DEVICES[username] || DEVICES.zhangsan
  const ips = (IPS[username] || IPS.zhangsan).map((x) => x.ip)
  const count = username === 'lisi' ? 46 : 24
  const items = []
  for (let i = 0; i < count; i++) {
    const app = APPS[(i + count) % APPS.length]
    const device = dev[i % dev.length]
    let status = 200
    if (username === 'lisi' && i % 5 === 0) status = 401
    if (username === 'lisi' && i % 11 === 0) status = 403
    if (username === 'wangwu' && i % 9 === 0) status = 404
    items.push({
      ts: ago(Math.round((i * DAY) / count / 60000) * 60000),
      app_id: app.id,
      url: app.url,
      method: i % 4 === 0 ? 'POST' : 'GET',
      status_code: status,
      src_ip: ips[i % ips.length],
    })
  }
  return items.sort((a, b) => b.ts - a.ts)
}

function mockDevices(username) {
  const dev = DEVICES[username] || DEVICES.zhangsan
  const allIps = IPS[username] || IPS.zhangsan
  return dev.map((d, di) => {
    const n = Math.max(1, Math.round(allIps.length / dev.length))
    const slice = allIps.slice(di * n, di * n + n)
    return {
      device_key: `mock-${username}-${di}`,
      ua_class: d.ua_class,
      browser: d.browser,
      browser_ver: d.browser_ver,
      managed: d.managed,
      ua_raw: d.ua_raw,
      last_active: fmt(ago(15 * 60000 * (di + 1))),
      ips: slice.map((x, ii) => ({
        ...x,
        first_seen: fmt(ago((7 - ii) * DAY)),
        last_seen: fmt(ago(ii === 0 ? 15 * 60000 * (di + 1) : (ii + 1) * DAY)),
      })),
    }
  })
}

function mockDetail(username) {
  const u = USERS.find((x) => x.username === username) || USERS[0]
  const history = { lisi: [
    { ts: ago(6 * DAY), from: 'low', to: 'medium', policy: '陌生 IP 短时间批量访问多个内部应用', reason: '1h 内访问 4 个应用，IP 来自 2 个国家' },
    { ts: ago(2 * DAY), from: 'medium', to: 'high', policy: '同一账号 1 分钟内连续 5 次 401', reason: '1min 内 401×7（app-finance）' },
  ], wangwu: [
    { ts: ago(3 * DAY), from: 'low', to: 'medium', policy: '异常终端访问核心应用', reason: '移动端 UA 访问 app-finance 导出接口' },
  ] }
  return {
    username: u.username,
    risk: u.risk,
    requests_24h: username === 'lisi' ? 128 : 34,
    ip_count_7d: u.ip_count_7d,
    country_count_7d: u.country_count_7d,
    device_count: u.device_count,
    timeline: mockTimeline(username),
    devices: mockDevices(username),
    risk_history: history[username] || [],
  }
}

// ---------------------------------------------------------------------------
// 对外接口（契约：docs/lba-api.md）
// ---------------------------------------------------------------------------

export const lbaApi = {
  loginOverview: () =>
    LBA_MOCK
      ? Promise.resolve({
          active_users_24h: 2386,
          devices_total: 4820,
          pending_anomaly_users: 16,
          high_risk_users: 3,
          window_desc: { ip_change_days: 7 },
        })
      : http.get('/lba/login/overview'),

  anomalyUsers: (params = {}) =>
    LBA_MOCK
      ? Promise.resolve((() => {
          const level = params.risk_level || ''
          const items = USERS.filter((u) => !level || u.risk === level).map((u) => ({
            ...u,
            last_active: fmt(u.last_active),
          }))
          return { items, total: items.length, page: params.page || 1, page_size: params.page_size || 20 }
        })())
      : http.get('/lba/login/anomaly-users', { params }),

  userProfile: (username) =>
    LBA_MOCK ? Promise.resolve(mockDetail(username)) : http.get(`/lba/profile/user/${encodeURIComponent(username)}`),
}
