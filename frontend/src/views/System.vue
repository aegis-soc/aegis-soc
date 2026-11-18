<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h2 class="page-title">
          {{ t('system.title') }}
          <el-tag size="small" type="info" effect="plain" style="margin-left: 8px; vertical-align: middle">v{{ status.version }}</el-tag>
        </h2>
        <p class="page-desc">{{ t('system.desc') }}</p>
      </div>
      <el-button :icon="Refresh" @click="load">{{ t('common.action.refresh') }}</el-button>
    </div>

    <div class="table-card" style="margin-bottom: 16px">
      <h3 style="margin: 0 0 14px; font-size: 14px">{{ t('system.status.title') }}</h3>
      <el-descriptions :column="3" border size="small">
        <el-descriptions-item :label="t('system.status.version')">{{ status.version }}</el-descriptions-item>
        <el-descriptions-item :label="t('system.status.env')">{{ status.app_env }}</el-descriptions-item>
        <el-descriptions-item :label="t('system.status.database')">{{ status.database }}</el-descriptions-item>
        <el-descriptions-item :label="t('system.status.taskMode')">{{ status.task_eager ? t('system.status.taskModeSync') : t('system.status.taskModeCelery') }}</el-descriptions-item>
        <el-descriptions-item :label="t('system.status.cache')">{{ cacheMode }}</el-descriptions-item>
        <el-descriptions-item :label="t('system.status.plugins')">{{ status.plugin_count }}</el-descriptions-item>
      </el-descriptions>
    </div>

    <div class="table-card" style="margin-bottom: 16px">
      <h3 style="margin: 0 0 8px; font-size: 14px">{{ t('system.update.title') }}</h3>
      <p class="text-muted" style="font-size: 12px; margin: 0 0 14px">{{ t('system.update.intro') }}</p>
      <el-descriptions :column="3" border size="small" style="margin-bottom: 14px">
        <el-descriptions-item :label="t('system.update.current')">v{{ status.version }}</el-descriptions-item>
        <el-descriptions-item :label="t('system.update.commit')">
          {{ !status.commit || status.commit === 'unknown' ? t('system.update.commitUnknown') : status.commit }}
        </el-descriptions-item>
        <el-descriptions-item :label="t('system.update.buildTime')">{{ status.build_time || '-' }}</el-descriptions-item>
      </el-descriptions>

      <el-button :loading="update.loading" :disabled="!isAdmin" @click="runCheck(true)">{{ t('system.update.check') }}</el-button>
      <span v-if="!isAdmin" class="text-muted" style="margin-left: 12px; font-size: 12px">{{ t('system.update.adminOnly') }}</span>

      <div v-if="update.checked" style="margin-top: 14px">
        <el-alert
          v-if="update.error" type="warning" show-icon :closable="false"
          :title="update.error"
          :description="t('system.update.errorDesc')"
        />
        <el-alert
          v-else-if="update.has_update" type="success" show-icon :closable="false"
          :title="t('system.update.found', { latest: update.latest_version })"
          :description="t('system.update.foundDesc', { current: status.version, published: update.published_at || t('system.update.unknown') })"
        />
        <el-alert
          v-else type="info" show-icon :closable="false"
          :title="t('system.update.upToDate')" :description="t('system.update.checkedAt', { time: update.checked_at })"
        />

        <div v-if="update.has_update && update.notes" class="release-block">
          <div class="release-title">{{ t('system.update.notes') }}{{ update.notes_truncated ? t('system.update.notesTruncated') : '' }}</div>
          <pre class="release-notes">{{ update.notes }}</pre>
        </div>

        <div v-if="update.has_update" class="release-block">
          <div class="release-title">{{ t('system.update.upgradeTitle') }}</div>
          <pre class="release-notes">{{ upgradeCmd }}</pre>
          <el-button size="small" @click="copyCmd">{{ t('system.update.copy') }}</el-button>
          <el-button v-if="update.html_url" size="small" link type="primary" @click="openRelease">{{ t('system.update.viewRelease') }}</el-button>
        </div>
      </div>
    </div>

    <div class="table-card" style="margin-bottom: 16px">
      <h3 style="margin: 0 0 8px; font-size: 14px">{{ t('system.kill.title') }}</h3>
      <p class="text-muted" style="font-size: 12px; margin: 0 0 14px">{{ t('system.kill.desc') }}</p>
      <el-switch v-model="killSwitch" :disabled="store.role !== 'admin'" :active-text="t('system.kill.on')" :inactive-text="t('system.kill.off')" @change="changeKill" />
      <span v-if="store.role !== 'admin'" class="text-muted" style="margin-left: 12px; font-size: 12px">{{ t('system.kill.adminOnly') }}</span>
    </div>

    <div class="table-card" style="margin-bottom: 16px">
      <h3 style="margin: 0 0 8px; font-size: 14px">{{ t('system.guard.title') }}</h3>
      <p class="text-muted" style="font-size: 12px; margin: 0 0 8px">
        {{ t('system.guard.desc1') }}<br>{{ t('system.guard.desc2') }}
      </p>
      <el-form label-width="140px" style="max-width: 600px">
        <el-form-item :label="t('system.guard.enforce')">
          <el-switch v-model="apiGuard.enforce" :disabled="!isAdmin" />
          <span class="text-muted" style="margin-left: 12px; font-size: 12px">
            {{ apiGuard.enforce ? t('system.guard.enabled', { n: apiGuard.count }) : t('system.guard.disabled') }}
          </span>
        </el-form-item>
        <el-form-item :label="t('system.guard.allowLabel')">
          <el-input
            v-model="apiGuard.allowlist" type="textarea" :rows="4" :disabled="!isAdmin"
            :placeholder="t('system.guard.placeholder')"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :disabled="!isAdmin" @click="saveGuard">{{ t('system.guard.save') }}</el-button>
          <span v-if="!isAdmin" class="text-muted" style="margin-left: 12px; font-size: 12px">{{ t('system.kill.adminOnly') }}</span>
        </el-form-item>
      </el-form>
    </div>

    <div class="table-card" style="margin-bottom: 16px">
      <h3 style="margin: 0 0 14px; font-size: 14px">{{ t('system.pwd.title') }}</h3>
      <el-form :model="pwd" label-width="120px" style="max-width: 460px">
        <el-form-item :label="t('system.pwd.old')"><el-input v-model="pwd.old_password" type="password" show-password /></el-form-item>
        <el-form-item :label="t('system.pwd.new')"><el-input v-model="pwd.new_password" type="password" show-password /></el-form-item>
        <el-button type="primary" @click="changePwd">{{ t('system.pwd.submit') }}</el-button>
      </el-form>
    </div>

    <div class="table-card">
      <h3 style="margin: 0 0 14px; font-size: 14px">{{ t('system.users.title') }}</h3>
      <el-table :data="users" size="small" stripe>
        <el-table-column prop="id" :label="t('system.users.id')" width="70" />
        <el-table-column prop="username" :label="t('system.users.username')" width="150" />
        <el-table-column prop="nickname" :label="t('system.users.nickname')" width="150" />
        <el-table-column prop="role_code" :label="t('system.users.role')" width="150">
          <template #default="{ row }">{{ roleLabel(row.role_code) }}</template>
        </el-table-column>
        <el-table-column prop="status" :label="t('system.users.status')" width="100">
          <template #default="{ row }">{{ row.status ? t('system.users.enabled') : t('system.users.disabled') }}</template>
        </el-table-column>
        <el-table-column prop="last_login_at" :label="t('system.users.lastLogin')" min-width="170" />
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '../api'
import { clearMustChange, store } from '../store'

const { t, te } = useI18n()
const status = reactive({ version: '-', commit: '', build_time: '', app_env: '-', database: '-', task_eager: false, plugin_count: 0, kill_switch: false })
const cacheMode = ref('-')
const killSwitch = ref(false)
const users = ref([])
const pwd = reactive({ old_password: '', new_password: '' })
const apiGuard = reactive({ enforce: false, allowlist: '', count: 0 })
const isAdmin = computed(() => store.role === 'admin')
const update = reactive({
  loading: false, checked: false, has_update: false,
  latest_version: '', published_at: '', notes: '', notes_truncated: false,
  html_url: '', checked_at: '', error: '',
})

function roleLabel(code) {
  if (!code) return '-'
  const key = `common.role.${code}`
  return te(key) ? t(key) : code
}

// 手工升级命令：只给「有新版」时展示，复制即用。刻意不显示一键按钮——
// 让 api 容器去重建自己，等于把 docker.sock 交给 web 进程，风险不对等。
const upgradeCmd = computed(() => [
  'cd ~/aegis-soc',
  'git pull --ff-only',
  "for f in sql/migrate_*.sql; do docker compose exec -T mysql sh -c 'mysql -uroot -p\"$MYSQL_ROOT_PASSWORD\" aegis_soc' < \"$f\"; done",
  'docker compose build api frontend && docker compose up -d',
].join('\n'))

async function load() {
  try {
    Object.assign(status, await api.systemStatus())
    const ks = await api.getKillSwitch()
    killSwitch.value = Boolean(ks.enabled)
    store.killSwitch = killSwitch.value
    users.value = (await api.users()).items || []
    if (isAdmin.value) await loadGuard()
  } catch (e) { /* 拦截器已提示 */ }
  try {
    const res = await fetch('/api/healthz')
    const body = await res.json()
    cacheMode.value = body?.data?.cache || '-'
  } catch (e) { cacheMode.value = '-' }
}
async function loadGuard() {
  const data = await api.systemSettings()
  apiGuard.enforce = Boolean(data.alert_ip_enforce)
  apiGuard.allowlist = data.alert_ip_allowlist || ''
  apiGuard.count = data.alert_ip_count || 0
}
async function saveGuard() {
  try {
    const data = await api.saveSystemSettings({
      alert_ip_enforce: apiGuard.enforce,
      alert_ip_allowlist: apiGuard.allowlist,
    })
    apiGuard.enforce = Boolean(data.alert_ip_enforce)
    apiGuard.allowlist = data.alert_ip_allowlist || ''
    apiGuard.count = data.alert_ip_count || 0
    ElMessage.success(apiGuard.enforce ? t('system.guard.savedOn', { n: apiGuard.count }) : t('system.guard.savedOff'))
  } catch (e) { /* 拦截器已提示 */ }
}
async function runCheck(force = false) {
  update.loading = true
  try {
    const data = await api.checkUpdate(force)
    Object.assign(update, {
      checked: true,
      has_update: Boolean(data.has_update),
      latest_version: data.latest_version || '',
      published_at: data.published_at || '',
      notes: data.notes || '',
      notes_truncated: Boolean(data.notes_truncated),
      html_url: data.html_url || '',
      checked_at: data.checked_at || '',
      // 后端返回的错误文案保持原样（多数来自 GitHub 状态码，属技术信息）
      error: data.error || '',
    })
    if (!data.error && !data.has_update) ElMessage.success(t('system.update.upToDate'))
    if (data.cached) ElMessage.info(t('system.update.cached'))
  } catch (e) { /* 拦截器已提示 */ } finally { update.loading = false }
}
async function copyCmd() {
  try {
    await navigator.clipboard.writeText(upgradeCmd.value)
    ElMessage.success(t('system.copied'))
  } catch (e) {
    ElMessage.warning(t('system.clipboardDenied'))
  }
}
function openRelease() {
  window.open(update.html_url, '_blank', 'noopener')
}
async function changeKill(value) {
  try {
    await api.setKillSwitch({ enabled: value, reason: t('system.kill.reason') })
    store.killSwitch = value
    ElMessage.success(value ? t('system.kill.enabled') : t('system.kill.disabled'))
  } catch (e) { killSwitch.value = !value }
}
async function changePwd() {
  try {
    await api.changePassword(pwd)
    clearMustChange()
    pwd.old_password = ''
    pwd.new_password = ''
    ElMessage.success(t('system.pwd.updated'))
  } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>

<style scoped>
.release-block { margin-top: 12px; }
.release-title { font-size: 12px; color: #606266; margin-bottom: 6px; }
.release-notes {
  margin: 0 0 8px;
  padding: 10px 12px;
  max-height: 220px;
  overflow: auto;
  background: #f7f8fa;
  border: 1px solid #ebeef5;
  border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
