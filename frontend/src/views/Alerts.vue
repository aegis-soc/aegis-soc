<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">{{ t('alerts.title') }}</h2><p class="page-desc">{{ t('alerts.desc') }}</p></div>
      <el-button type="primary" :icon="Plus" @click="openTest">{{ t('alerts.submitTest') }}</el-button>
    </div>
    <div class="filter-bar">
      <el-select v-model="query.status" :placeholder="t('alerts.statusPlaceholder')" clearable style="width: 150px">
        <el-option v-for="s in statusOptions" :key="s" :label="statusLabel(s)" :value="s" />
      </el-select>
      <el-input v-model="query.keyword" :placeholder="t('alerts.keywordPlaceholder')" clearable style="width: 220px" @keyup.enter="load" />
      <el-button type="primary" @click="load">{{ t('common.action.search') }}</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe v-loading="loading">
        <el-table-column prop="received_at" :label="t('alerts.col.receivedAt')" width="170" />
        <el-table-column prop="alert_id" :label="t('alerts.col.alertId')" width="180" show-overflow-tooltip />
        <el-table-column prop="title" :label="t('alerts.col.title')" min-width="180" show-overflow-tooltip />
        <el-table-column prop="source_system" :label="t('alerts.col.source')" width="100" />
        <el-table-column prop="risk_level" :label="t('alerts.col.risk')" width="90">
          <template #default="{ row }">{{ riskLabel(row.risk_level) }}</template>
        </el-table-column>
        <el-table-column prop="status" :label="t('alerts.col.status')" width="130">
          <template #default="{ row }"><el-tag size="small" :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag></template>
        </el-table-column>
        <el-table-column :label="t('alerts.col.iocCount')" width="80">
          <template #default="{ row }">{{ (row.ioc_candidates || []).length }}</template>
        </el-table-column>
        <el-table-column :label="t('alerts.col.actions')" width="90" fixed="right">
          <template #default="{ row }"><el-button link type="primary" @click="detail(row)">{{ t('common.action.detail') }}</el-button></template>
        </el-table-column>
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>

    <el-dialog v-model="detailVisible" :title="t('alerts.detail.title')" width="640px">
      <el-descriptions :column="2" border size="small" v-if="current">
        <el-descriptions-item :label="t('alerts.col.alertId')">{{ current.alert_id }}</el-descriptions-item>
        <el-descriptions-item :label="t('alerts.col.source')">{{ current.source_system }}</el-descriptions-item>
        <el-descriptions-item :label="t('alerts.col.title')" :span="2">{{ current.title }}</el-descriptions-item>
        <el-descriptions-item :label="t('alerts.test.risk')">{{ riskLabel(current.risk_level) }}</el-descriptions-item>
        <el-descriptions-item :label="t('alerts.detail.confidence')">{{ current.confidence }}</el-descriptions-item>
        <el-descriptions-item :label="t('alerts.col.status')">{{ statusLabel(current.status) }}</el-descriptions-item>
        <el-descriptions-item :label="t('alerts.detail.processMsg')">{{ current.process_msg || '-' }}</el-descriptions-item>
        <el-descriptions-item :label="t('alerts.detail.srcIp')" :span="2">{{ (current.src_ips || []).join(', ') || '-' }}</el-descriptions-item>
        <el-descriptions-item :label="t('alerts.detail.iocCandidates')" :span="2">
          <el-tag v-for="(c, i) in (current.ioc_candidates || [])" :key="i" size="small" style="margin: 2px">{{ c.ioc_type }}:{{ c.value }}</el-tag>
        </el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <el-dialog v-model="testVisible" :title="t('alerts.test.title')" width="480px">
      <el-form :model="testForm" label-width="110px">
        <el-form-item :label="t('alerts.test.alertTitle')"><el-input v-model="testForm.title" /></el-form-item>
        <el-form-item :label="t('alerts.test.ip')"><el-input v-model="testForm.ip" :placeholder="t('alerts.test.ipPlaceholder')" /></el-form-item>
        <el-form-item :label="t('alerts.test.risk')">
          <el-select v-model="testForm.risk_level" style="width: 100%">
            <el-option v-for="s in riskOptions" :key="s" :label="riskLabel(s)" :value="s" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('alerts.test.confidence')"><el-input-number v-model="testForm.confidence" :min="0" :max="100" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="testVisible = false">{{ t('common.action.cancel') }}</el-button><el-button type="primary" @click="submitTest">{{ t('alerts.test.submit') }}</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { api } from '../api'

const { t, te } = useI18n()
const statusOptions = ['pending', 'processed', 'whitelisted', 'ignored', 'failed']
const riskOptions = ['critical', 'high', 'medium', 'low']
const rows = ref([])
const total = ref(0)
const loading = ref(false)
const query = reactive({ page: 1, page_size: 20, status: '', keyword: '' })
const detailVisible = ref(false)
const testVisible = ref(false)
const current = ref(null)
const testForm = reactive({ title: '', ip: '8.8.8.8', risk_level: 'high', confidence: 90 })

// 枚举值仍按英文 code 存取与筛选，只有显示时翻——过滤条件不能跟着语言变
function enumLabel(namespace, value) {
  if (!value) return '-'
  const key = `${namespace}.${value}`
  return te(key) ? t(key) : value
}
const statusLabel = (value) => enumLabel('enums.alertStatus', value)
const riskLabel = (value) => enumLabel('enums.risk', value)

function statusType(s) {
  return ({ processed: 'success', whitelisted: 'warning', failed: 'danger', ignored: 'info' })[s] || 'primary'
}
function openTest() {
  // 标题会作为数据落库，所以按当前语言给个默认值
  if (!testForm.title) testForm.title = t('alerts.test.defaultTitle')
  testVisible.value = true
}
async function load() {
  loading.value = true
  try {
    const params = { ...query }
    Object.keys(params).forEach((k) => { if (params[k] === '') delete params[k] })
    const data = await api.alerts(params)
    rows.value = data.items
    total.value = data.total
  } catch (e) { /* 拦截器已提示 */ } finally { loading.value = false }
}
function detail(row) { current.value = row; detailVisible.value = true }
async function submitTest() {
  const ips = testForm.ip.split(',').map((s) => s.trim()).filter(Boolean)
  try {
    const res = await api.genericAlert({
      title: testForm.title, src_ips: ips, risk_level: testForm.risk_level,
      confidence: testForm.confidence, source_system: 'generic', alert_id: `manual-${Date.now()}`,
    })
    ElMessage.success(t('alerts.test.accepted', { n: res.task_count }))
    testVisible.value = false
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
