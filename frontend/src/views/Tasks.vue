<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">任务日志</h2><p class="page-desc">异步下发任务、失败重试、人工审批与设备回执日志</p></div>
      <el-button :icon="Refresh" @click="load">刷新</el-button>
    </div>
    <div class="filter-bar">
      <el-select v-model="query.task_status" placeholder="任务状态" clearable style="width: 150px">
        <el-option v-for="s in ['PENDING','RUNNING','SUCCESS','FAILED','RETRY','CANCELED','APPROVING','REJECTED']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-select v-model="query.operation" placeholder="操作类型" clearable style="width: 140px">
        <el-option v-for="s in ['BLOCK','UNBLOCK','QUERY']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-input v-model="query.keyword" placeholder="IOC 关键字" clearable style="width: 200px" @keyup.enter="load" />
      <el-button type="primary" @click="load">查询</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe v-loading="loading">
        <el-table-column prop="task_no" label="任务号" width="190" class-name="mono" />
        <el-table-column prop="ioc_value" label="IOC" min-width="140" class-name="mono" />
        <el-table-column prop="operation" label="操作" width="100">
          <template #default="{ row }"><el-tag size="small" :type="row.operation === 'BLOCK' ? 'danger' : 'success'">{{ row.operation }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="plugin_code" label="插件" width="130" />
        <el-table-column prop="task_status" label="状态" width="120">
          <template #default="{ row }"><el-tag size="small" :type="statusType(row.task_status)">{{ row.task_status }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="retry_count" label="重试" width="70" />
        <el-table-column prop="result_msg" label="结果" min-width="180" show-overflow-tooltip />
        <el-table-column prop="created_at" label="创建时间" width="170" />
        <el-table-column label="操作" width="230" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="detail(row)">详情</el-button>
            <el-button link v-if="['FAILED','RETRY','CANCELED'].includes(row.task_status)" @click="retry(row)">重试</el-button>
            <el-button link v-if="row.task_status === 'APPROVING'" type="success" @click="approve(row, true)">通过</el-button>
            <el-button link v-if="row.task_status === 'APPROVING'" type="warning" @click="approve(row, false)">拒绝</el-button>
            <el-button link v-if="!['SUCCESS','CANCELED','REJECTED'].includes(row.task_status)" type="danger" @click="cancel(row)">取消</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>

    <el-dialog v-model="detailVisible" title="任务详情与执行日志" width="760px">
      <el-descriptions :column="3" border size="small" v-if="current">
        <el-descriptions-item label="任务号">{{ current.task_no }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ current.task_status }}</el-descriptions-item>
        <el-descriptions-item label="操作">{{ current.operation }}</el-descriptions-item>
        <el-descriptions-item label="IOC">{{ current.ioc_value }}</el-descriptions-item>
        <el-descriptions-item label="插件">{{ current.plugin_code }}</el-descriptions-item>
        <el-descriptions-item label="重试次数">{{ current.retry_count }} / {{ current.max_retry }}</el-descriptions-item>
        <el-descriptions-item label="结果" :span="3">{{ current.result_msg || '-' }}</el-descriptions-item>
      </el-descriptions>
      <h4 style="margin: 18px 0 8px; font-size: 13px">请求 / 响应留痕</h4>
      <el-table :data="logs" size="small" stripe max-height="280">
        <el-table-column prop="attempt" label="第几次" width="80" />
        <el-table-column prop="success" label="成功" width="80">
          <template #default="{ row }"><el-tag size="small" :type="row.success ? 'success' : 'danger'">{{ row.success ? '是' : '否' }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="http_status" label="HTTP" width="80" />
        <el-table-column prop="request_payload" label="请求(脱敏)" min-width="200" show-overflow-tooltip />
        <el-table-column prop="response_payload" label="设备响应" min-width="200" show-overflow-tooltip />
        <el-table-column prop="error_msg" label="错误" min-width="160" show-overflow-tooltip />
      </el-table>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '../api'

const rows = ref([])
const logs = ref([])
const total = ref(0)
const loading = ref(false)
const detailVisible = ref(false)
const current = ref(null)
const query = reactive({ page: 1, page_size: 20, task_status: '', operation: '', keyword: '' })

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
async function retry(row) { try { await api.retryTask(row.id); ElMessage.success('已重新下发'); load() } catch (e) { /* 拦截器已提示 */ } }
async function cancel(row) { try { await api.cancelTask(row.id); ElMessage.success('已取消'); load() } catch (e) { /* 拦截器已提示 */ } }
async function approve(row, value) { try { await api.approveTask(row.id, value, value ? '' : '人工拒绝'); ElMessage.success(value ? '已通过' : '已拒绝'); load() } catch (e) { /* 拦截器已提示 */ } }
onMounted(load)
</script>
