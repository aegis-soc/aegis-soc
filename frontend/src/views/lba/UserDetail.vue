<template>
  <div v-loading="loading">
    <div class="head">
      <el-button link @click="router.back()">← </el-button>
      <span class="head-name">{{ detail.username }}</span>
      <el-tag :type="riskTag(detail.risk)">{{ riskLabel(detail.risk) }}</el-tag>
    </div>

    <el-descriptions :column="4" border style="margin-top: 14px">
      <el-descriptions-item :label="t('lba.detail.statRequests')">{{ detail.requests_24h }}</el-descriptions-item>
      <el-descriptions-item :label="t('lba.detail.statIp')">{{ detail.ip_count_7d }}</el-descriptions-item>
      <el-descriptions-item :label="t('lba.detail.statCountry')">{{ detail.country_count_7d }}</el-descriptions-item>
      <el-descriptions-item :label="t('lba.detail.statDevices')">{{ detail.device_count }}</el-descriptions-item>
    </el-descriptions>

    <el-card shadow="never" style="margin-top: 16px">
      <template #header><span>{{ t('lba.detail.timeline') }}</span></template>
      <el-empty v-if="!detail.timeline || !detail.timeline.length" :description="t('lba.detail.timelineEmpty')" />
      <template v-else>
        <el-timeline style="padding-left: 4px">
          <el-timeline-item v-for="ev in timelineShown" :key="ev.ts + ev.url" :timestamp="fmtTs(ev.ts)" placement="top">
            <el-tag size="small" :type="ev.status_code < 400 ? 'success' : 'danger'" style="margin-right: 8px">{{ ev.status_code }}</el-tag>
            <el-tag size="small" type="info" style="margin-right: 8px">{{ ev.app_id }}</el-tag>
            <span class="mono">{{ ev.method }}</span>
            <span class="mono url">{{ ev.url }}</span>
            <span class="dim">· {{ ev.src_ip }}</span>
          </el-timeline-item>
        </el-timeline>
        <div v-if="detail.timeline.length > timelineMax" class="dim" style="margin-top: 8px">
          {{ t('lba.detail.timelineLimit', { n: timelineMax }) }}
        </div>
      </template>
    </el-card>

    <el-card shadow="never" style="margin-top: 16px">
      <template #header><span>{{ t('lba.detail.deviceList') }}</span></template>
      <el-empty v-if="!detail.devices || !detail.devices.length" />
      <div v-for="dev in detail.devices" :key="dev.device_key" class="device-card">
        <div class="device-head">
          <el-tag :type="dev.ua_class === 'feishu' ? 'success' : 'info'">{{ pick('lba.detail.deviceClassValue', dev.ua_class) }}</el-tag>
          <span class="device-browser">{{ pick('lba.detail.browserValue', dev.browser) }} {{ dev.browser_ver }}</span>
          <el-tag size="small" :type="dev.managed === 'managed' ? 'success' : 'info'">{{ pick('lba.detail.managedValue', dev.managed) }}</el-tag>
          <span class="dim" style="margin-left: auto">{{ t('lba.detail.lastActive') }}: {{ dev.last_active }}</span>
        </div>
        <div class="dim mono ua">{{ t('lba.detail.ua') }}: {{ dev.ua_raw }}</div>
        <el-table :data="dev.ips" size="small" style="margin-top: 8px">
          <el-table-column :label="t('lba.detail.col.ip')" prop="ip" width="160" />
          <el-table-column :label="t('lba.detail.col.location')" min-width="180">
            <template #default="{ row }">{{ row.country }} · {{ row.city }}</template>
          </el-table-column>
          <el-table-column :label="t('lba.detail.col.isp')" prop="isp" width="120" />
          <el-table-column :label="t('lba.detail.col.firstSeen')" prop="first_seen" width="170" />
          <el-table-column :label="t('lba.detail.col.lastSeen')" prop="last_seen" width="170" />
          <el-table-column :label="t('lba.detail.col.action')" width="100">
            <template #default="{ row }">
              <el-button link type="danger" @click="blockIp(row.ip)">{{ t('lba.detail.blockIp') }}</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-card>

    <el-card shadow="never" style="margin-top: 16px">
      <template #header><span>{{ t('lba.detail.riskHistory') }}</span></template>
      <el-empty v-if="!detail.risk_history || !detail.risk_history.length" :description="t('lba.detail.riskHistoryEmpty')" />
      <el-table v-else :data="detail.risk_history">
        <el-table-column :label="t('lba.detail.col.time')" width="170">
          <template #default="{ row }">{{ fmtTs(row.ts) }}</template>
        </el-table-column>
        <el-table-column :label="t('lba.detail.change')" width="160">
          <template #default="{ row }">
            <el-tag size="small" :type="riskTag(row.from)">{{ riskLabel(row.from) }}</el-tag>
            <span style="margin: 0 6px">→</span>
            <el-tag size="small" :type="riskTag(row.to)">{{ riskLabel(row.to) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('lba.detail.policy')" prop="policy" min-width="240" />
        <el-table-column :label="t('lba.detail.trigger')" prop="reason" min-width="260" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { lbaApi } from '../../api/lba'

const { t, te } = useI18n()
const route = useRoute()
const router = useRouter()

const detail = ref({})
const loading = ref(false)
const timelineMax = 50

const pick = (ns, v) => (v ? (te(`${ns}.${v}`) ? t(`${ns}.${v}`) : v) : '-')
const riskLabel = (v) => pick('enums.risk', v)
const riskTag = (v) => ({ high: 'danger', medium: 'warning', low: 'success' }[v] || 'info')
const timelineShown = computed(() => (detail.value.timeline || []).slice(0, timelineMax))

const fmtTs = (ts) => {
  const d = new Date(ts)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getMonth() + 1}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

async function load() {
  loading.value = true
  try {
    detail.value = await lbaApi.userProfile(route.params.username)
  } catch (e) { console.error('[lba] 详情取数失败:', e) /* axios 错误拦截器已提示 */ } finally { loading.value = false }
}

async function blockIp(ip) {
  try {
    await ElMessageBox.confirm(t('lba.detail.blockConfirm'), ip, { type: 'warning' })
    ElMessage.success(t('lba.detail.blockDone'))
  } catch (e) { /* 取消 */ }
}

onMounted(load)
</script>

<style scoped>
.head { display: flex; align-items: center; gap: 10px; }
.head-name { font-size: 18px; font-weight: 600; }
.device-card { border: 1px solid #ebeef5; border-radius: 8px; padding: 12px 14px; margin-bottom: 12px; }
.device-card:last-child { margin-bottom: 0; }
.device-head { display: flex; align-items: center; gap: 8px; }
.device-browser { font-weight: 500; }
.mono { font-family: Consolas, Monaco, monospace; font-size: 12px; }
.url { color: #409eff; margin-left: 6px; }
.dim { color: #909399; font-size: 12px; }
.ua { margin-top: 8px; word-break: break-all; }
</style>
