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
      { path: 'dashboard', name: 'dashboard', component: () => import('../views/Dashboard.vue'), meta: { titleKey: 'menu.dashboard', icon: 'Odometer' } },
      { path: 'inspections', name: 'inspections', component: () => import('../views/Inspection.vue'), meta: { titleKey: 'menu.inspections', icon: 'Search' } },
      { path: 'patrol', name: 'patrol', component: () => import('../views/Patrol.vue'), meta: { titleKey: 'menu.patrol', icon: 'Aim' } },
      { path: 'chat', name: 'chat', component: () => import('../views/Chat.vue'), meta: { titleKey: 'menu.chat', icon: 'ChatDotRound' } },
      { path: 'alerts', name: 'alerts', component: () => import('../views/Alerts.vue'), meta: { titleKey: 'menu.alerts', icon: 'Bell' } },
      { path: 'blacklist-ip', name: 'blacklist-ip', component: () => import('../views/BlacklistIP.vue'), meta: { titleKey: 'menu.blacklistIp', icon: 'Lock' } },
      { path: 'blacklist-domain', name: 'blacklist-domain', component: () => import('../views/BlacklistDomain.vue'), meta: { titleKey: 'menu.blacklistDomain', icon: 'Link' } },
      { path: 'whitelist-ip', name: 'whitelist-ip', component: () => import('../views/WhitelistIP.vue'), meta: { titleKey: 'menu.whitelistIp', icon: 'Unlock' } },
      { path: 'devices', name: 'devices', component: () => import('../views/Devices.vue'), meta: { titleKey: 'menu.devices', icon: 'Monitor' } },
      { path: 'plugins', name: 'plugins', component: () => import('../views/Plugins.vue'), meta: { titleKey: 'menu.plugins', icon: 'Grid' } },
      { path: 'policies', name: 'policies', component: () => import('../views/Policies.vue'), meta: { titleKey: 'menu.policies', icon: 'Setting' } },
      { path: 'tasks', name: 'tasks', component: () => import('../views/Tasks.vue'), meta: { titleKey: 'menu.tasks', icon: 'List' } },
      { path: 'audit', name: 'audit', component: () => import('../views/Audit.vue'), meta: { titleKey: 'menu.auditOps', icon: 'Document' } },
      { path: 'system', name: 'system', component: () => import('../views/System.vue'), meta: { titleKey: 'menu.system', icon: 'Tools' } },
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
