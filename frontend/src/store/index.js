import { reactive } from 'vue'

const TOKEN_KEY = 'gl_token'
const ROLE_KEY = 'gl_role'
const USER_KEY = 'gl_user'
const CHANGE_KEY = 'gl_must_change'
const LANG_KEY = 'gl_lang'

export const store = reactive({
  token: localStorage.getItem(TOKEN_KEY) || '',
  role: localStorage.getItem(ROLE_KEY) || '',
  username: localStorage.getItem(USER_KEY) || '',
  mustChange: localStorage.getItem(CHANGE_KEY) === '1',
  killSwitch: false,
  // 版本信息来自 /system/status，不在前端写死，避免两处版本号打架
  version: '',
  commit: '',
  buildTime: '',
  // 默认固定中文，不跟随浏览器；只有手动切过才记住
  locale: localStorage.getItem(LANG_KEY) === 'en-US' ? 'en-US' : 'zh-CN',
})

export function setAuth(data) {
  store.token = data.access_token
  store.role = data.role_code
  store.mustChange = Boolean(data.must_change_password)
  localStorage.setItem(TOKEN_KEY, store.token)
  localStorage.setItem(ROLE_KEY, store.role)
  localStorage.setItem(CHANGE_KEY, store.mustChange ? '1' : '0')
}

export function setLocale(locale) {
  store.locale = locale === 'en-US' ? 'en-US' : 'zh-CN'
  localStorage.setItem(LANG_KEY, store.locale)
}

export function setUser(username) {
  store.username = username
  localStorage.setItem(USER_KEY, username)
}

export function clearMustChange() {
  store.mustChange = false
  localStorage.setItem(CHANGE_KEY, '0')
}

export function logout() {
  store.token = ''
  store.role = ''
  store.username = ''
  store.mustChange = false
  ;[TOKEN_KEY, ROLE_KEY, USER_KEY, CHANGE_KEY].forEach((k) => localStorage.removeItem(k))
}
