import { createRouter, createWebHistory } from 'vue-router'
import { store } from '../store'
import MainLayout from '../layouts/MainLayout.vue'

const routes = [
  { path: '/login', name: 'login', component: () => import('../views/Login.vue'), meta: { public: true } },
  {
    path: '/',
    component: MainLayout,
    redirect: '/dashboard',
    children: [
      { path: 'dashboard', name: 'dashboard', component: () => import('../views/Dashboard.vue'), meta: { title: '首页大盘', icon: 'Odometer' } },
      { path: 'inspections', name: 'inspections', component: () => import('../views/Inspection.vue'), meta: { title: 'AI 巡检', icon: 'Search' } },
      { path: 'patrol', name: 'patrol', component: () => import('../views/Patrol.vue'), meta: { title: '日志巡检', icon: 'Aim' } },
      { path: 'alerts', name: 'alerts', component: () => import('../views/Alerts.vue'), meta: { title: '告警中心', icon: 'Bell' } },
      { path: 'blacklist-ip', name: 'blacklist-ip', component: () => import('../views/BlacklistIP.vue'), meta: { title: 'IP 黑名单', icon: 'Lock' } },
      { path: 'blacklist-domain', name: 'blacklist-domain', component: () => import('../views/BlacklistDomain.vue'), meta: { title: '域名黑名单', icon: 'Link' } },
      { path: 'whitelist-ip', name: 'whitelist-ip', component: () => import('../views/WhitelistIP.vue'), meta: { title: 'IP 白名单', icon: 'Unlock' } },
      { path: 'devices', name: 'devices', component: () => import('../views/Devices.vue'), meta: { title: '设备管理', icon: 'Monitor' } },
      { path: 'plugins', name: 'plugins', component: () => import('../views/Plugins.vue'), meta: { title: '插件管理', icon: 'Grid' } },
      { path: 'policies', name: 'policies', component: () => import('../views/Policies.vue'), meta: { title: '策略配置', icon: 'Setting' } },
      { path: 'tasks', name: 'tasks', component: () => import('../views/Tasks.vue'), meta: { title: '任务中心', icon: 'List' } },
      { path: 'audit', name: 'audit', component: () => import('../views/Audit.vue'), meta: { title: '操作审计', icon: 'Document' } },
      { path: 'system', name: 'system', component: () => import('../views/System.vue'), meta: { title: '系统设置', icon: 'Tools' } },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach((to) => {
  if (to.meta.public) return true
  if (!store.token) return { path: '/login', query: { redirect: to.fullPath } }
  return true
})

export default router
