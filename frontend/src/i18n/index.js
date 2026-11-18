import { createI18n } from 'vue-i18n'
import { watch } from 'vue'
import { store } from '../store'

// 一个页面一个语言文件，文件名即命名空间（patrol.js → t('patrol.xxx')）。
// 这样多人并行改不同页面时不会在同一个 json 里打架，也不用每加一页就改一次 index。
const zhModules = import.meta.glob('./locales/zh-CN/*.js', { eager: true })
const enModules = import.meta.glob('./locales/en-US/*.js', { eager: true })

function collect(modules) {
  const messages = {}
  for (const [path, mod] of Object.entries(modules)) {
    const name = path.split('/').pop().replace(/\.js$/, '')
    messages[name] = mod.default || {}
  }
  return messages
}

export const messages = {
  'zh-CN': collect(zhModules),
  'en-US': collect(enModules),
}

export const i18n = createI18n({
  legacy: false,
  globalInjection: true,
  locale: store.locale,
  fallbackLocale: 'zh-CN',
  // 漏翻的 key 在开发环境打日志，生产环境静默回退中文，不刷控制台
  missingWarn: import.meta.env.DEV,
  fallbackWarn: import.meta.env.DEV,
  messages,
})

// 语言切换只改 store；这里同步给 vue-i18n 与 <html lang>，
// 前者负责文案响应式刷新，后者影响浏览器翻译提示与字体回退。
watch(
  () => store.locale,
  (locale) => {
    i18n.global.locale.value = locale
    document.documentElement.lang = locale
  },
  { immediate: true },
)

export default i18n
