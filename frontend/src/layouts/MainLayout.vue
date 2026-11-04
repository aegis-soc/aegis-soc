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
      <el-menu :default-active="activeMenu" router background-color="#1f2a3d" text-color="#c0c8d6" active-text-color="#ffffff">
        <el-menu-item v-for="item in menus" :key="item.path" :index="item.path">
          <el-icon><component :is="item.icon" /></el-icon>
          <span>{{ item.title }}</span>
        </el-menu-item>
      </el-menu>
      <div class="aside-foot">v1.0.0 · Apache 2.0</div>
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
  { path: '/alerts', title: '告警中心', icon: 'Bell' },
  { path: '/blacklist-ip', title: 'IP 黑名单', icon: 'Lock' },
  { path: '/blacklist-domain', title: '域名黑名单', icon: 'Link' },
  { path: '/whitelist-ip', title: 'IP 白名单', icon: 'Unlock' },
  { path: '/devices', title: '设备管理', icon: 'Monitor' },
  { path: '/plugins', title: '插件管理', icon: 'Grid' },
  { path: '/policies', title: '策略配置', icon: 'Setting' },
  { path: '/tasks', title: '任务中心', icon: 'List' },
  { path: '/audit', title: '操作审计', icon: 'Document' },
  { path: '/system', title: '系统设置', icon: 'Tools' },
]
const activeMenu = computed(() => route.path)
const currentTitle = computed(() => route.meta.title || '宙斯盾 Aegis')
const roleLabel = computed(() => ({ admin: '系统管理员', operator: '安全运营', auditor: '只读审计员' })[store.role] || store.role)

async function refreshStatus() {
  try {
    const status = await api.systemStatus()
    store.killSwitch = Boolean(status.kill_switch)
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
