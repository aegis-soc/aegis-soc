<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">{{ t('tasks.title') }}</h2><p class="page-desc">{{ t('tasks.desc') }}</p></div>
      <el-button :icon="Refresh" @click="load">{{ t('common.action.refresh') }}</el-button>
    </div>
    <div class="filter-bar">
      <el-select v-model="query.task_status" :placeholder="t('tasks.statusPlaceholder')" clearable style="width: 160px">
        <el-option v-for="s in statusOptions" :key="s" :label="enumLabel('enums.taskStatus', s)" :value="s" />
      </el-select>
      <el-select v-model="query.operation" :placeholder="t('tasks.opPlaceholder')" clearable style="width: 140px">
        <el-option v-for="s in opOptions" :key="s" :label="enumLabel('enums.operation', s)" :value="s" />
      </el-select>
      <el-input v-model="query.keyword" :placeholder="t('tasks.keywordPlaceholder')" clearable style="width: 200px" @keyup.enter="load" />
      <el-button type="primary" @click="load">{{ t('common.action.search') }}</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe v-loading="loading">
        <el-table-column prop="task_no" :label="t('tasks.col.taskNo')" width="190" class-name="mono" />
        <el-table-column prop="ioc_value" :label="t('tasks.col.ioc')" min-width="140" class-name="mono" />
        <el-table-column prop="operation" :label="t('tasks.col.operation')" width="110">
          <template #default="{ row }"><el-tag size="small" :type="row.operation === 'BLOCK' ? 'danger' : 'success'">{{ enumLabel('enums.operation', row.operation) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="plugin_code" :label="t('tasks.col.plugin')" width="130" />
        <el-table-column prop="task_status" :label="t('tasks.col.status')" width="130">
          <template #default="{ row }"><el-tag size="small" :type="statusType(row.task_status)">{{ enumLabel('enums.taskStatus', row.task_status) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="retry_count" :label="t('tasks.col.retry')" width="70" />
        <el-table-column prop="result_msg" :label="t('tasks.col.result')" min-width="180" show-overflow-tooltip />
        <el-table-column prop="created_at" :label="t('tasks.col.createdAt')" width="170" />
        <el-table-column :label="t('tasks.col.actions')" width="240" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="detail(row)">{{ t('tasks.act.detail') }}</el-button>
            <el-button link v-if="['FAILED','RETRY','CANCELED'].includes(row.task_status)" @click="retry(row)">{{ t('tasks.act.retry') }}</el-button>
            <el-button link v-if="row.task_status === 'APPROVING'" type="success" @click="approve(row, true)">{{ t('tasks.act.approve') }}</el-button>
            <el-button link v-if="row.task_status === 'APPROVING'" type="warning" @click="approve(row, false)">{{ t('tasks.act.reject') }}</el-button>
            <el-button link v-if="!['SUCCESS','CANCELED','REJECTED'].includes(row.task_status)" type="danger" @click="cancel(row)">{{ t('tasks.act.cancel') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>

    <el-dialog v-model="detailVisible" :title="t('tasks.detail.title')" width="780px">
      <el-descriptions :column="3" border size="small" v-if="current">
        <el-descriptions-item :label="t('tasks.detail.taskNo')">{{ current.task_no }}</el-descriptions-item>
        <el-descriptions-item :label="t('tasks.col.status')">{{ enumLabel('enums.taskStatus', current.task_status) }}</el-descriptions-item>
        <el-descriptions-item :label="t('tasks.col.operation')">{{ enumLabel('enums.operation', current.operation) }}</el-descriptions-item>
        <el-descriptions-item :label="t('tasks.col.ioc')">{{ current.ioc_value }}</el-descriptions-item>
        <el-descriptions-item :label="t('tasks.col.plugin')">{{ current.plugin_code }}</el-descriptions-item>
        <el-descriptions-item :label="t('tasks.detail.retryCount')">{{ current.retry_count }} / {{ current.max_retry }}</el-descriptions-item>
        <el-descriptions-item :label="t('tasks.detail.result')" :span="3">{{ current.result_msg || '-' }}</el-descriptions-item>
      </el-descriptions>
      <h4 style="margin: 18px 0 8px; font-size: 13px">{{ t('tasks.logs.title') }}</h4>
      <el-table :data="logs" size="small" stripe max-height="280">
        <el-table-column prop="attempt" :label="t('tasks.logs.attempt')" width="90" />
        <el-table-column prop="success" :label="t('tasks.logs.success')" width="80">
          <template #default="{ row }"><el-tag size="small" :type="row.success ? 'success' : 'danger'">{{ row.success ? t('common.label.yes') : t('common.label.no') }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="http_status" label="HTTP" width="80" />
        <el-table-column prop="request_payload" :label="t('tasks.logs.request')" min-width="200" show-overflow-tooltip />
        <el-table-column prop="response_payload" :label="t('tasks.logs.response')" min-width="200" show-overflow-tooltip />
        <el-table-column prop="error_msg" :label="t('tasks.logs.error')" min-width="160" show-overflow-tooltip />
      </el-table>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '../api'

const { t, te } = useI18n()
const statusOptions = ['PENDING', 'RUNNING', 'SUCCESS', 'FAILED', 'RETRY', 'CANCELED', 'APPROVING', 'REJECTED']
const opOptions = ['BLOCK', 'UNBLOCK', 'QUERY']
const rows = ref([])
const logs = ref([])
const total = ref(0)
const loading = ref(false)
const detailVisible = ref(false)
const current = ref(null)
const query = reactive({ page: 1, page_size: 20, task_status: '', operation: '', keyword: '' })

function enumLabel(namespace, value) {
  if (!value) return '-'
  const key = `${namespace}.${value}`
  return te(key) ? t(key) : value
}
function statusType(s) {
  return ({ SUCCESS: 'success', FAILED: 'danger', RETRY: 'warning', CANCELED: 'info', REJECTED: 'info', APPROVING: 'warning' })[s] || 'primary'
}
async function load() {
  loading.value = true
  try {
    const params = { ...query }
    Object.keys(params).forEach((k) => { if (params[k] === '') delete params[k] })
    const data = await api.tasks(params)
    rows.value = data.items
    total.value = data.total
  } catch (e) { /* 拦截器已提示 */ } finally { loading.value = false }
}
async function detail(row) {
  try {
    const data = await api.task(row.id)
    current.value = data.task
    logs.value = data.logs
    detailVisible.value = true
  } catch (e) { /* 拦截器已提示 */ }
}
async function retry(row) { try { await api.retryTask(row.id); ElMessage.success(t('tasks.toast.resent')); load() } catch (e) { /* 拦截器已提示 */ } }
async function cancel(row) { try { await api.cancelTask(row.id); ElMessage.success(t('tasks.toast.canceled')); load() } catch (e) { /* 拦截器已提示 */ } }
async function approve(row, value) {
  try {
    // 拒绝原因会落库，按当前界面语言写入
    await api.approveTask(row.id, value, value ? '' : t('tasks.toast.rejectReason'))
    ElMessage.success(value ? t('tasks.toast.approved') : t('tasks.toast.rejected'))
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
