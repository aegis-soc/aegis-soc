<template>
  <div>
    <el-alert v-if="LBA_MOCK" type="info" :closable="false" show-icon style="margin-bottom: 16px"
      :title="t('lba.anomaly.title')" description="演示数据（mock），非实际统计结果。接口契约见 docs/lba-api.md。" />

    <div class="range-bar">
      <span class="range-label">{{ t('lba.range.pick') }}</span>
      <el-radio-group v-model="range" @change="load">
        <el-radio-button v-for="r in LBA_RANGES" :key="r" :value="r">
          {{ t('lba.range.' + r) }}
        </el-radio-button>
      </el-radio-group>
    </div>

    <el-row v-if="range" :gutter="16">
      <el-col v-for="card in kpiCards" :key="card.key" :span="6">
        <el-card shadow="never" class="kpi-card">
          <div class="kpi-num" :class="card.tone">{{ card.value }}</div>
          <div class="kpi-label">{{ card.label }}</div>
        </el-card>
      </el-col>
    </el-row>

    <div v-if="range && windowDesc.fetched !== undefined" class="window-desc">
      {{ t('lba.windowDesc', {
        start: windowDesc.window_start || '-', end: windowDesc.window_end || '-',
        n: windowDesc.fetched, first: windowDesc.data_first_seen || '-', last: windowDesc.data_last_seen || '-' }) }}
    </div>

    <el-empty v-if="!range" :description="t('lba.range.pickHint')" />

    <el-card v-else shadow="never" style="margin-top: 16px">
      <template #header>
        <div class="card-head">
          <span>{{ t('lba.anomaly.title') }} · {{ t('lba.range.' + range) }}</span>
          <el-select v-model="riskFilter" clearable :placeholder="t('lba.anomaly.filterRisk')" style="width: 160px" @change="load">
            <el-option v-for="lv in ['high', 'medium', 'low']" :key="lv" :value="lv" :label="riskLabel(lv)" />
          </el-select>
        </div>
      </template>

      <el-table :data="rows" v-loading="loading" @row-click="openDetail" row-class-name="clickable">
        <el-table-column :label="t('lba.anomaly.col.user')" prop="username" width="150" show-overflow-tooltip />
        <el-table-column :label="t('lba.anomaly.col.name')" min-width="110">
          <template #default="{ row }">{{ row.display_name || '-' }}</template>
        </el-table-column>
        <el-table-column :label="t('lba.anomaly.col.device')" min-width="200">
          <template #default="{ row }">
            <span>{{ t('lba.anomaly.devices', { n: row.device_count }) }}</span>
            <el-tag v-for="tp in row.device_types" :key="tp" size="small" style="margin-left: 6px" type="info">
              {{ pick('lba.detail.deviceClassValue', tp) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('lba.anomaly.col.ipChange')" min-width="180">
          <template #default="{ row }">{{ t('lba.anomaly.ipChange', { n: row.ip_count_7d, m: row.country_count_7d }) }}</template>
        </el-table-column>
        <el-table-column :label="t('lba.anomaly.col.risk')" width="100">
          <template #default="{ row }"><el-tag :type="riskTag(row.risk)">{{ riskLabel(row.risk) }}</el-tag></template>
        </el-table-column>
        <el-table-column :label="t('lba.anomaly.col.pending')" prop="pending_events" width="110" />
        <el-table-column :label="t('lba.anomaly.col.lastActive')" prop="last_active" width="180" />
        <el-table-column :label="t('lba.anomaly.col.action')" width="110">
          <template #default="{ row }">
            <el-button link type="primary" @click.stop="openDetail(row)">{{ t('lba.anomaly.viewDetail') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { LBA_MOCK, LBA_RANGES, lbaApi } from '../../api/lba'

const { t, te } = useI18n()
const router = useRouter()

const overview = ref({})
const rows = ref([])
const loading = ref(false)
const riskFilter = ref('')
const range = ref('')   // 空 = 未选择：进入页面不自动打 Graylog，点按钮才取数

const windowDesc = computed(() => overview.value.window_desc || {})

const pick = (ns, v) => (v ? (te(`${ns}.${v}`) ? t(`${ns}.${v}`) : v) : '-')
const riskLabel = (v) => pick('enums.risk', v)
const riskTag = (v) => ({ high: 'danger', medium: 'warning', low: 'success' }[v] || 'info')

const kpiCards = computed(() => {
  const suffix = range.value ? `（${t('lba.range.' + range.value)}）` : ''
  return [
    { key: 'active', value: overview.value.active_users ?? '-', label: t('lba.kpi.activeUsers') + suffix, tone: '' },
    { key: 'devices', value: overview.value.devices_total ?? '-', label: t('lba.kpi.devices') + suffix, tone: '' },
    { key: 'pending', value: overview.value.pending_anomaly_users ?? '-', label: t('lba.kpi.pendingUsers') + suffix, tone: 'warn' },
    { key: 'high', value: overview.value.high_risk_users ?? '-', label: t('lba.kpi.highRiskUsers') + suffix, tone: 'danger' },
  ]
})

async function load() {
  loading.value = true
  try {
    if (!range.value) return
    const [ov, list] = await Promise.all([
      lbaApi.loginOverview(range.value),
      lbaApi.anomalyUsers({ range: range.value, risk_level: riskFilter.value || undefined, page: 1, page_size: 20 }),
    ])
    overview.value = ov
    rows.value = list.items
  } catch (e) { console.error('[lba] 取数失败:', e) /* axios 错误拦截器已提示 */ } finally { loading.value = false }
}

function openDetail(row) {
  router.push({ path: `/lba/user/${encodeURIComponent(row.username)}`,
                query: range.value ? { range: range.value } : {} })
}
</script>

<style scoped>
.range-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.range-label { color: var(--el-text-color-secondary); font-size: 14px; }
.kpi-card { text-align: center; }
.window-desc { color: #909399; font-size: 12px; margin: 8px 4px 0; }
.kpi-num { font-size: 28px; font-weight: 600; line-height: 1.3; }
.kpi-num.warn { color: #e6a23c; }
.kpi-num.danger { color: #f56c6c; }
.kpi-label { color: #909399; font-size: 13px; margin-top: 4px; }
.card-head { display: flex; justify-content: space-between; align-items: center; }
:deep(.clickable) { cursor: pointer; }
</style>
