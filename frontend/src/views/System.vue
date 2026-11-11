<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">系统设置</h2><p class="page-desc">运行状态、全局熔断开关、API 调用来源限制、账号与口令管理</p></div>
      <el-button :icon="Refresh" @click="load">刷新</el-button>
    </div>

    <div class="table-card" style="margin-bottom: 16px">
      <h3 style="margin: 0 0 14px; font-size: 14px">运行状态</h3>
      <el-descriptions :column="3" border size="small">
        <el-descriptions-item label="版本">{{ status.version }}</el-descriptions-item>
        <el-descriptions-item label="运行环境">{{ status.app_env }}</el-descriptions-item>
        <el-descriptions-item label="数据库">{{ status.database }}</el-descriptions-item>
        <el-descriptions-item label="任务模式">{{ status.task_eager ? '同步（调试）' : 'Celery 异步' }}</el-descriptions-item>
        <el-descriptions-item label="缓存">{{ cacheMode }}</el-descriptions-item>
        <el-descriptions-item label="已加载插件">{{ status.plugin_count }}</el-descriptions-item>
      </el-descriptions>
    </div>

    <div class="table-card" style="margin-bottom: 16px">
      <h3 style="margin: 0 0 8px; font-size: 14px">全局自动封禁熔断</h3>
      <p class="text-muted" style="font-size: 12px; margin: 0 0 14px">
        开启后新告警只留痕、不产生任何封禁任务；已生成的任务不受影响。误封演练或设备维护时建议开启。
      </p>
      <el-switch v-model="killSwitch" :disabled="store.role !== 'admin'" active-text="已熔断（暂停自动封禁）" inactive-text="正常运行" @change="changeKill" />
      <span v-if="store.role !== 'admin'" class="text-muted" style="margin-left: 12px; font-size: 12px">仅系统管理员可修改</span>
    </div>

    <div class="table-card" style="margin-bottom: 16px">
      <h3 style="margin: 0 0 8px; font-size: 14px">API 调用来源限制</h3>
      <p class="text-muted" style="font-size: 12px; margin: 0 0 14px">
        只作用于告警接入接口 <code>/api/v1/alerts/graylog</code>：开启后仅允许名单内的 IP 调用，其余一律 403。
        默认关闭；名单留空等于不限制。保存即时生效，不需要重启容器。<br>
        来源 IP 取 nginx 的 <code>$remote_addr</code>（<code>X-Real-IP</code>），客户端自带的 <code>X-Forwarded-For</code> 不参与判断。
      </p>
      <el-form label-width="110px" style="max-width: 560px">
        <el-form-item label="启用来源限制">
          <el-switch v-model="apiGuard.enforce" :disabled="!isAdmin" />
          <span class="text-muted" style="margin-left: 12px; font-size: 12px">
            {{ apiGuard.enforce ? `已启用，放行 ${apiGuard.count} 条` : '未启用（任何来源都可调用）' }}
          </span>
        </el-form-item>
        <el-form-item label="允许的 IP">
          <el-input
            v-model="apiGuard.allowlist" type="textarea" :rows="4" :disabled="!isAdmin"
            placeholder="每行一个 IP 或网段，也可用逗号分隔，例如：&#10;10.32.239.10&#10;10.46.0.0/16"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :disabled="!isAdmin" @click="saveGuard">保存</el-button>
          <span v-if="!isAdmin" class="text-muted" style="margin-left: 12px; font-size: 12px">仅系统管理员可修改</span>
        </el-form-item>
      </el-form>
    </div>

    <div class="table-card" style="margin-bottom: 16px">
      <h3 style="margin: 0 0 14px; font-size: 14px">修改口令</h3>
      <el-form :model="pwd" label-width="100px" style="max-width: 460px">
        <el-form-item label="原口令"><el-input v-model="pwd.old_password" type="password" show-password /></el-form-item>
        <el-form-item label="新口令"><el-input v-model="pwd.new_password" type="password" show-password /></el-form-item>
        <el-button type="primary" @click="changePwd">确认修改</el-button>
      </el-form>
    </div>

    <div class="table-card">
      <h3 style="margin: 0 0 14px; font-size: 14px">系统用户</h3>
      <el-table :data="users" size="small" stripe>
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="username" label="用户名" width="150" />
        <el-table-column prop="nickname" label="昵称" width="150" />
        <el-table-column prop="role_code" label="角色" width="140" />
        <el-table-column prop="status" label="状态" width="90">
          <template #default="{ row }">{{ row.status ? '启用' : '禁用' }}</template>
        </el-table-column>
        <el-table-column prop="last_login_at" label="最后登录" min-width="170" />
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '../api'
import { clearMustChange, store } from '../store'

const status = reactive({ version: '-', app_env: '-', database: '-', task_eager: false, plugin_count: 0, kill_switch: false })
const cacheMode = ref('-')
const killSwitch = ref(false)
const users = ref([])
const pwd = reactive({ old_password: '', new_password: '' })
const apiGuard = reactive({ enforce: false, allowlist: '', count: 0 })
const isAdmin = computed(() => store.role === 'admin')

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
    ElMessage.success(apiGuard.enforce ? `已保存，放行 ${apiGuard.count} 条来源` : '已保存，来源限制已关闭')
  } catch (e) { /* 拦截器已提示 */ }
}
async function changeKill(value) {
  try {
    await api.setKillSwitch({ enabled: value, reason: '管理界面操作' })
    store.killSwitch = value
    ElMessage.success(value ? '熔断已开启，自动封禁暂停' : '熔断已关闭，自动封禁恢复')
  } catch (e) { killSwitch.value = !value }
}
async function changePwd() {
  try {
    await api.changePassword(pwd)
    clearMustChange()
    pwd.old_password = ''
    pwd.new_password = ''
    ElMessage.success('口令已更新')
  } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
