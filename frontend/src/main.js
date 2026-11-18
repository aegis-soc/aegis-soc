import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'
import App from './App.vue'
import router from './router'
import i18n from './i18n'
import './styles/main.css'

const app = createApp(App)
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component)
}
// Element Plus 内置文案（分页、日期选择器）改由 App.vue 的 el-config-provider 控制
app.use(ElementPlus)
app.use(i18n)
app.use(router)
app.mount('#app')
