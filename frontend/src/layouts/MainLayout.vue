<template>
  <el-container style="height: 100%">
    <el-aside width="220px" class="aside">
      <div class="brand">
        <div class="brand-mark">AS</div>
        <div>
          <div class="brand-name">{{ t('common.app.name') }}</div>
          <div class="brand-sub">{{ t('common.app.sub') }}</div>
        </div>
      </div>
      <el-menu :key="activeGroupKey" :default-active="activeMenu" :default-openeds="openedGroups" router background-color="#1f2a3d" text-color="#c0c8d6" active-text-color="#ffffff">
        <template v-for="item in menus" :key="item.path || item.index">
          <el-sub-menu v-if="item.children" :index="item.index">
            <template #title>
              <el-icon><component :is="item.icon" /></el-icon>
              <span>{{ t(item.titleKey) }}</span>
            </template>
            <el-menu-item v-for="child in item.children" :key="child.path" :index="child.path">
              <el-icon><component :is="child.icon" /></el-icon>
              <span>{{ t(child.titleKey) }}</span>
            </el-menu-item>
          </el-sub-menu>
          <el-menu-item v-else :index="item.path">
            <el-icon><component :is="item.icon" /></el-icon>
            <span>{{ t(item.titleKey) }}</span>
          </el-menu-item>
        </template>
      </el-menu>
      <div class="aside-foot">
        <span class="foot-version" :title="buildTimeText">
          v{{ store.version || '-' }}<span v-if="store.commit && store.commit !== 'unknown'"> · {{ store.commit }}</span>
        </span>
        <span class="lang-switch" :title="t('common.lang.label')">
          <a :class="{ on: store.locale === 'zh-CN' }" @click="switchLang('zh-CN')">{{ t('common.lang.zh') }}</a>
          <i>/</i>
          <a :class="{ on: store.locale === 'en-US' }" @click="switchLang('en-US')">EN</a>
        </span>
      </div>
    </el-aside>

    <el-container>
      <el-header class="header">
        <div class="header-left">
          <span class="crumb">{{ currentTitle }}</span>
          <el-tag v-if="store.killSwitch" type="danger" size="small" effect="dark">{{ t('layout.killSwitchOn') }}</el-tag>
          <el-tag v-else type="success" size="small" effect="plain">{{ t('layout.killSwitchOff') }}</el-tag>
        </div>
        <div class="header-right">
          <el-tag size="small" type="info">{{ roleLabel }}</el-tag>
          <span class="username">{{ store.username || t('common.tip.notLoggedIn') }}</span>
          <el-button link type="primary" @click="doLogout">{{ t('layout.logout') }}</el-button>
        </div>
      </el-header>
      <el-main class="main">
        <el-alert
          v-if="store.mustChange" type="warning" show-icon :closable="false"
          :title="t('layout.mustChangeTitle')" :description="t('layout.mustChangeDesc')"
          style="margin-bottom: 16px"
        />
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { ElMessageBox } from 'element-plus'
import { api } from '../api'
import { logout, setLocale, store } from '../store'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()

// 菜单只存 key，文案在语言包里——加一种语言不用碰这个文件
const menus = [
  { path: '/dashboard', titleKey: 'menu.dashboard', icon: 'Odometer' },
  {
    index: 'g-ai', titleKey: 'menu.aiOps', icon: 'MagicStick',
    children: [
      { path: '/inspections', titleKey: 'menu.inspections', icon: 'Search' },
      { path: '/patrol', titleKey: 'menu.patrol', icon: 'Aim' },
      { path: '/chat', titleKey: 'menu.chat', icon: 'ChatDotRound' },
    ],
  },
  { path: '/alerts', titleKey: 'menu.alerts', icon: 'Bell' },
  {
    index: 'g-ioc', titleKey: 'menu.ioc', icon: 'Filter',
    children: [
      { path: '/blacklist-ip', titleKey: 'menu.blacklistIp', icon: 'Lock' },
      { path: '/blacklist-domain', titleKey: 'menu.blacklistDomain', icon: 'Link' },
      { path: '/whitelist-ip', titleKey: 'menu.whitelistIp', icon: 'Unlock' },
    ],
  },
  {
    index: 'g-lba', titleKey: 'menu.lba', icon: 'DataAnalysis',
    children: [
      { path: '/lba/login', titleKey: 'menu.loginCenter', icon: 'User' },
    ],
  },
  {
    index: 'g-policy', titleKey: 'menu.policy', icon: 'SetUp',
    children: [
      { path: '/policies', titleKey: 'menu.policies', icon: 'Operation' },
      { path: '/devices', titleKey: 'menu.devices', icon: 'Monitor' },
      { path: '/plugins', titleKey: 'menu.plugins', icon: 'Grid' },
    ],
  },
  {
    index: 'g-audit', titleKey: 'menu.audit', icon: 'Document',
    children: [
      { path: '/tasks', titleKey: 'menu.tasks', icon: 'List' },
      { path: '/audit', titleKey: 'menu.auditOps', icon: 'Document' },
    ],
  },
  { path: '/system', titleKey: 'menu.system', icon: 'Tools' },
]
const activeMenu = computed(() => route.path)

// 只展开当前页面所在分组，其余收起——一级菜单少一半，扫一眼就能定位
const openedGroups = computed(() => {
  const group = menus.find((item) => (item.children || []).some((child) => child.path === route.path))
  return group ? [group.index] : []
})

// 面包屑显示「分组 / 页面」，比单看页面名更能说明自己在哪
function menuTitle(path) {
  for (const item of menus) {
    if (item.path === path) return t(item.titleKey)
    const child = (item.children || []).find((c) => c.path === path)
    if (child) return `${t(item.titleKey)} / ${t(child.titleKey)}`
  }
  return t(route.meta.titleKey || 'layout.crumbFallback')
}
const currentTitle = computed(() => menuTitle(route.path))
// 换分组时重新挂载菜单，保证只有当前分组是展开的
const activeGroupKey = computed(() => openedGroups.value[0] || 'root')
const roleLabel = computed(() => {
  const key = `common.role.${store.role}`
  return store.role && t(key) !== key ? t(key) : store.role
})
const buildTimeText = computed(() =>
  t('layout.builtAt', { time: store.buildTime || '-' }) + ' · ' + t('layout.license'),
)

function switchLang(locale) {
  if (store.locale === locale) return
  setLocale(locale)
}

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
  await ElMessageBox.confirm(t('common.tip.logoutConfirm'), t('common.tip.prompt'), { type: 'warning' }).catch(() => 'cancel')
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
.aside-foot {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  color: #66738a; font-size: 11px; padding: 12px 14px; border-top: 1px solid #2c3a52;
}
.foot-version { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.lang-switch { display: flex; align-items: center; gap: 4px; flex: none; }
.lang-switch a { color: #7c8aa0; cursor: pointer; text-decoration: none; }
.lang-switch a:hover { color: #c0c8d6; }
.lang-switch a.on { color: #ffffff; font-weight: 600; }
.lang-switch i { font-style: normal; color: #445066; }
.header { background: #fff; border-bottom: 1px solid #ebeef5; display: flex; align-items: center; justify-content: space-between; }
.header-left, .header-right { display: flex; align-items: center; gap: 12px; }
.crumb { font-size: 15px; font-weight: 600; }
.username { font-size: 13px; color: #606266; }
.main { padding: 20px; overflow-y: auto; }
</style>
