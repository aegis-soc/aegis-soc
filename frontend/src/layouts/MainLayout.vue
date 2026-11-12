<template>
  <el-container style="height: 100%">
    <el-aside width="220px" class="aside">
      <div class="brand">
        <div class="brand-mark">AS</div>
        <div>
          <div class="brand-name">宙斯盾 Aegis</div>
          <div class="brand-sub">通用安全运营自动化 AI+SOC</div>
        </div>
      </div>
      <el-menu :key="activeGroupKey" :default-active="activeMenu" :default-openeds="openedGroups" router background-color="#1f2a3d" text-color="#c0c8d6" active-text-color="#ffffff">
        <template v-for="item in menus" :key="item.path || item.index">
          <el-sub-menu v-if="item.children" :index="item.index">
            <template #title>
              <el-icon><component :is="item.icon" /></el-icon>
              <span>{{ item.title }}</span>
            </template>
            <el-menu-item v-for="child in item.children" :key="child.path" :index="child.path">
              <el-icon><component :is="child.icon" /></el-icon>
              <span>{{ child.title }}</span>
            </el-menu-item>
          </el-sub-menu>
          <el-menu-item v-else :index="item.path">
            <el-icon><component :is="item.icon" /></el-icon>
            <span>{{ item.title }}</span>
          </el-menu-item>
        </template>
      </el-menu>
      <div class="aside-foot" :title="store.buildTime ? `构建于 ${store.buildTime}` : ''">
        v{{ store.version || '-' }}<span v-if="store.commit && store.commit !== 'unknown'"> · {{ store.commit }}</span> · Apache 2.0
      </div>
    </el-aside>

    <el-container>
      <el-header class="header">
        <div class="header-left">
          <span class="crumb">{{ currentTitle }}</span>
          <el-tag v-if="store.killSwitch" type="danger" size="small" effect="dark">自动封禁已熔断</el-tag>
          <el-tag v-else type="success" size="small" effect="plain">自动封禁运行中</el-tag>
        </div>
        <div class="header-right">
          <el-tag size="small" type="info">{{ roleLabel }}</el-tag>
          <span class="username">{{ store.username || '未登录' }}</span>
          <el-button link type="primary" @click="doLogout">退出</el-button>
        </div>
      </el-header>
      <el-main class="main">
        <el-alert
          v-if="store.mustChange" type="warning" show-icon :closable="false"
          title="首次登录请尽快修改默认口令" description="可在「系统设置」页面修改，修改后本提示自动消失。"
          style="margin-bottom: 16px"
        />
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessageBox } from 'element-plus'
import { api } from '../api'
import { logout, store } from '../store'

const route = useRoute()
const router = useRouter()
const menus = [
  { path: '/dashboard', title: '首页大盘', icon: 'Odometer' },
  {
    index: 'g-ai', title: 'AI 运营', icon: 'MagicStick',
    children: [
      { path: '/inspections', title: 'AI 巡检', icon: 'Search' },
      { path: '/patrol', title: '日志巡检', icon: 'Aim' },
      { path: '/chat', title: '人机对话', icon: 'ChatDotRound' },
    ],
  },
  { path: '/alerts', title: '告警中心', icon: 'Bell' },
  {
    index: 'g-ioc', title: '黑白名单', icon: 'Filter',
    children: [
      { path: '/blacklist-ip', title: 'IP 黑名单', icon: 'Lock' },
      { path: '/blacklist-domain', title: '域名黑名单', icon: 'Link' },
      { path: '/whitelist-ip', title: 'IP 白名单', icon: 'Unlock' },
    ],
  },
  {
    index: 'g-policy', title: '策略配置', icon: 'SetUp',
    children: [
      { path: '/policies', title: '策略列表', icon: 'Operation' },
      { path: '/devices', title: '设备管理', icon: 'Monitor' },
      { path: '/plugins', title: '插件管理', icon: 'Grid' },
    ],
  },
  {
    index: 'g-audit', title: '日志审计', icon: 'Document',
    children: [
      { path: '/tasks', title: '任务日志', icon: 'List' },
      { path: '/audit', title: '操作审计', icon: 'Document' },
    ],
  },
  { path: '/system', title: '系统设置', icon: 'Tools' },
]
const activeMenu = computed(() => route.path)

// 只展开当前页面所在分组，其余收起——一级菜单少一半，扫一眼就能定位
const openedGroups = computed(() => {
  const group = menus.find((item) => (item.children || []).some((child) => child.path === route.path))
  return group ? [group.index] : []
})

function menuTitle(path) {
  for (const item of menus) {
    if (item.path === path) return item.title
    const child = (item.children || []).find((c) => c.path === path)
    if (child) return `${item.title} / ${child.title}`
  }
  return route.meta.title || '宙斯盾 Aegis'
}
const currentTitle = computed(() => menuTitle(route.path))
// 换分组时重新挂载菜单，保证只有当前分组是展开的
const activeGroupKey = computed(() => openedGroups.value[0] || 'root')
const roleLabel = computed(() => ({ admin: '系统管理员', operator: '安全运营', auditor: '只读审计员' })[store.role] || store.role)

async function refreshStatus() {
  try {
    const status = await api.systemStatus()
    store.killSwitch = Boolean(status.kill_switch)
    store.version = status.version || ''
    store.commit = status.commit || ''
    store.buildTime = status.build_time || ''
  } catch (e) { /* 已由拦截器提示 */ }
}
onMounted(refreshStatus)

async function doLogout() {
  await ElMessageBox.confirm('确认退出登录？', '提示', { type: 'warning' }).catch(() => 'cancel')
    .then((action) => {
      if (action === 'cancel') return
      logout()
      router.push('/login')
    })
}
</script>

<style scoped>
.aside { background: #1f2a3d; display: flex; flex-direction: column; }
.brand { display: flex; align-items: center; gap: 10px; padding: 20px 16px; border-bottom: 1px solid #2c3a52; }
.brand-mark { width: 34px; height: 34px; border-radius: 8px; background: #3b82f6; color: #fff; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; }
.brand-name { color: #fff; font-size: 14px; font-weight: 600; }
.brand-sub { color: #8b97ab; font-size: 10px; margin-top: 2px; }
.aside :deep(.el-menu) { border-right: none; flex: 1; }
.aside-foot { color: #66738a; font-size: 11px; padding: 14px 16px; border-top: 1px solid #2c3a52; }
.header { background: #fff; border-bottom: 1px solid #ebeef5; display: flex; align-items: center; justify-content: space-between; }
.header-left, .header-right { display: flex; align-items: center; gap: 12px; }
.crumb { font-size: 15px; font-weight: 600; }
.username { font-size: 13px; color: #606266; }
.main { padding: 20px; overflow-y: auto; }
</style>
