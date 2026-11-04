<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h2 class="page-title">首页大盘</h2>
        <p class="page-desc">告警、IOC、设备与任务的整体运行态势</p>
      </div>
      <el-button :icon="Refresh" @click="load">刷新</el-button>
    </div>

    <el-alert v-if="data.kill_switch" type="danger" show-icon :closable="false" title="全局熔断已开启"
      description="自动封禁任务暂停生成，告警仅留痕。可在系统设置中关闭。" style="margin-bottom: 16px" />

    <div class="stat-grid">
      <div class="stat-card"><div class="stat-label">今日告警</div><div class="stat-value">{{ data.alerts_today }}</div><div class="stat-hint">累计 {{ data.alerts_total }} 条</div></div>
      <div class="stat-card"><div class="stat-label">活跃黑名单</div><div class="stat-value">{{ data.ioc_active }}</div><div class="stat-hint">已过期 {{ data.ioc_expired }}</div></div>
      <div class="stat-card"><div class="stat-label">白名单</div><div class="stat-value">{{ data.whitelist_count }}</div><div class="stat-hint">受保护地址 / 网段</div></div>
      <div class="stat-card"><div class="stat-label">在线设备</div><div class="stat-value">{{ data.device_online }}</div><div class="stat-hint">共 {{ data.device_total }} 台</div></div>
      <div class="stat-card"><div class="stat-label">待处理任务</div><div class="stat-value">{{ data.task_pending }}</div><div class="stat-hint">含重试与待审批</div></div>
      <div class="stat-card"><div class="stat-label">成功 / 失败任务</div><div class="stat-value">{{ data.task_success }} / {{ data.task_failed }}</div><div class="stat-hint">累计 {{ data.task_total }} 条</div></div>
    </div>

    <div class="table-card" style="margin-bottom: 16px">
      <h3 style="margin: 0 0 12px; font-size: 14px">风险分布</h3>
      <el-space wrap>
        <el-tag v-for="(count, level) in data.risk_distribution" :key="level" :type="riskType(level)" effect="light">
          {{ level }}：{{ count }}
        </el-tag>
        <span v-if="!Object.keys(data.risk_distribution || {}).length" class="text-muted">暂无告警</span>
      </el-space>
    </div>

    <div class="table-card">
      <h3 style="margin: 0 0 12px; font-size: 14px">最近告警</h3>
      <el-table :data="data.recent_alerts || []" size="small" stripe>
        <el-table-column prop="received_at" label="时间" width="170" />
        <el-table-column prop="title" label="告警标题" min-width="180" show-overflow-tooltip />
        <el-table-column prop="source_system" label="来源" width="100" />
        <el-table-column prop="risk_level" label="风险" width="90">
          <template #default="{ row }"><el-tag size="small" :type="riskType(row.risk_level)">{{ row.risk_level || '-' }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="status" label="处置状态" width="120" />
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '../api'

const data = reactive({
  alerts_today: 0, alerts_total: 0, ioc_active: 0, ioc_expired: 0,
  whitelist_count: 0, device_online: 0, device_total: 0,
  task_pending: 0, task_success: 0, task_failed: 0, task_total: 0,
  kill_switch: false, risk_distribution: {}, recent_alerts: [],
})

function riskType(level) {
  return ({ critical: 'danger', high: 'warning', medium: 'primary', low: 'info' })[level] || 'info'
}

async function load() {
  try {
    Object.assign(data, await api.dashboard())
  } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
