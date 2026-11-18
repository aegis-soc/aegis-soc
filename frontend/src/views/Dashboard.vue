<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h2 class="page-title">{{ t('dashboard.title') }}</h2>
        <p class="page-desc">{{ t('dashboard.desc') }}</p>
      </div>
      <el-button :icon="Refresh" @click="load">{{ t('common.action.refresh') }}</el-button>
    </div>

    <el-alert v-if="data.kill_switch" type="danger" show-icon :closable="false" :title="t('dashboard.kill.title')"
      :description="t('dashboard.kill.desc')" style="margin-bottom: 16px" />

    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-label">{{ t('dashboard.stat.alertsToday') }}</div>
        <div class="stat-value">{{ data.alerts_today }}</div>
        <div class="stat-hint">{{ t('dashboard.stat.alertsTotal', { n: data.alerts_total }) }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">{{ t('dashboard.stat.iocActive') }}</div>
        <div class="stat-value">{{ data.ioc_active }}</div>
        <div class="stat-hint">{{ t('dashboard.stat.iocDetail', { expired: data.ioc_expired, rejected: data.ioc_rejected }) }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">{{ t('dashboard.stat.whitelist') }}</div>
        <div class="stat-value">{{ data.whitelist_count }}</div>
        <div class="stat-hint">{{ t('dashboard.stat.whitelistHint') }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">{{ t('dashboard.stat.deviceOnline') }}</div>
        <div class="stat-value">{{ data.device_online }}</div>
        <div class="stat-hint">{{ t('dashboard.stat.deviceTotal', { n: data.device_total }) }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">{{ t('dashboard.stat.taskPending') }}</div>
        <div class="stat-value">{{ data.task_pending }}</div>
        <div class="stat-hint">{{ t('dashboard.stat.taskPendingHint') }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">{{ t('dashboard.stat.taskResult') }}</div>
        <div class="stat-value">{{ data.task_success }} / {{ data.task_failed }}</div>
        <div class="stat-hint">{{ t('dashboard.stat.taskTotal', { n: data.task_total }) }}</div>
      </div>
    </div>

    <div class="table-card" style="margin-bottom: 16px">
      <h3 style="margin: 0 0 12px; font-size: 14px">{{ t('dashboard.risk.title') }}</h3>
      <el-space wrap>
        <el-tag v-for="(count, level) in data.risk_distribution" :key="level" :type="riskType(level)" effect="light">
          {{ riskLabel(level) }}：{{ count }}
        </el-tag>
        <span v-if="!Object.keys(data.risk_distribution || {}).length" class="text-muted">{{ t('dashboard.risk.empty') }}</span>
      </el-space>
    </div>

    <div class="table-card">
      <h3 style="margin: 0 0 12px; font-size: 14px">{{ t('dashboard.recent.title') }}</h3>
      <el-table :data="data.recent_alerts || []" size="small" stripe>
        <el-table-column prop="received_at" :label="t('dashboard.recent.time')" width="170" />
        <el-table-column prop="title" :label="t('dashboard.recent.alertTitle')" min-width="180" show-overflow-tooltip />
        <el-table-column prop="source_system" :label="t('dashboard.recent.source')" width="100" />
        <el-table-column prop="risk_level" :label="t('dashboard.recent.risk')" width="90">
          <template #default="{ row }"><el-tag size="small" :type="riskType(row.risk_level)">{{ riskLabel(row.risk_level) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="status" :label="t('dashboard.recent.status')" width="120" />
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive } from 'vue'
import { useI18n } from 'vue-i18n'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '../api'

const { t, te } = useI18n()
const data = reactive({
  alerts_today: 0, alerts_total: 0, ioc_active: 0, ioc_expired: 0, ioc_rejected: 0,
  whitelist_count: 0, device_online: 0, device_total: 0,
  task_pending: 0, task_success: 0, task_failed: 0, task_total: 0,
  kill_switch: false, risk_distribution: {}, recent_alerts: [],
})

function riskType(level) {
  return ({ critical: 'danger', high: 'warning', medium: 'primary', low: 'info' })[level] || 'info'
}

// 风险级别由后端给英文枚举，显示时再翻；遇到没见过的值就原样显示，不吞掉
function riskLabel(level) {
  if (!level) return '-'
  const key = `dashboard.risk.${level}`
  return te(key) ? t(key) : level
}

async function load() {
  try {
    Object.assign(data, await api.dashboard())
  } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
