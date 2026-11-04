<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">告警中心</h2><p class="page-desc">Graylog / 通用告警接入记录与处置结果</p></div>
      <el-button type="primary" :icon="Plus" @click="testVisible = true">提交测试告警</el-button>
    </div>
    <div class="filter-bar">
      <el-select v-model="query.status" placeholder="处置状态" clearable style="width: 150px">
        <el-option v-for="s in ['pending','processed','whitelisted','ignored','failed']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-input v-model="query.keyword" placeholder="标题关键字" clearable style="width: 220px" @keyup.enter="load" />
      <el-button type="primary" @click="load">查询</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe v-loading="loading">
        <el-table-column prop="received_at" label="接收时间" width="170" />
        <el-table-column prop="alert_id" label="告警 ID" width="180" show-overflow-tooltip />
        <el-table-column prop="title" label="标题" min-width="180" show-overflow-tooltip />
        <el-table-column prop="source_system" label="来源" width="100" />
        <el-table-column prop="risk_level" label="风险" width="90" />
        <el-table-column prop="status" label="处置状态" width="120">
          <template #default="{ row }"><el-tag size="small" :type="statusType(row.status)">{{ row.status }}</el-tag></template>
        </el-table-column>
        <el-table-column label="IOC 数" width="80">
          <template #default="{ row }">{{ (row.ioc_candidates || []).length }}</template>
        </el-table-column>
        <el-table-column label="操作" width="90" fixed="right">
          <template #default="{ row }"><el-button link type="primary" @click="detail(row)">详情</el-button></template>
        </el-table-column>
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>

    <el-dialog v-model="detailVisible" title="告警详情" width="640px">
      <el-descriptions :column="2" border size="small" v-if="current">
        <el-descriptions-item label="告警 ID">{{ current.alert_id }}</el-descriptions-item>
        <el-descriptions-item label="来源">{{ current.source_system }}</el-descriptions-item>
        <el-descriptions-item label="标题" :span="2">{{ current.title }}</el-descriptions-item>
        <el-descriptions-item label="风险等级">{{ current.risk_level }}</el-descriptions-item>
        <el-descriptions-item label="置信度">{{ current.confidence }}</el-descriptions-item>
        <el-descriptions-item label="处置状态">{{ current.status }}</el-descriptions-item>
        <el-descriptions-item label="处置说明">{{ current.process_msg || '-' }}</el-descriptions-item>
        <el-descriptions-item label="源 IP" :span="2">{{ (current.src_ips || []).join(', ') || '-' }}</el-descriptions-item>
        <el-descriptions-item label="IOC 候选" :span="2">
          <el-tag v-for="(c, i) in (current.ioc_candidates || [])" :key="i" size="small" style="margin: 2px">{{ c.ioc_type }}:{{ c.value }}</el-tag>
        </el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <el-dialog v-model="testVisible" title="提交通用测试告警" width="480px">
      <el-form :model="testForm" label-width="100px">
        <el-form-item label="标题"><el-input v-model="testForm.title" /></el-form-item>
        <el-form-item label="源 IP"><el-input v-model="testForm.ip" placeholder="如 8.8.8.8，多个用逗号分隔" /></el-form-item>
        <el-form-item label="风险等级">
          <el-select v-model="testForm.risk_level" style="width: 100%">
            <el-option v-for="s in ['critical','high','medium','low']" :key="s" :label="s" :value="s" />
          </el-select>
        </el-form-item>
        <el-form-item label="置信度"><el-input-number v-model="testForm.confidence" :min="0" :max="100" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="testVisible = false">取消</el-button><el-button type="primary" @click="submitTest">提交</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { api } from '../api'

const rows = ref([])
const total = ref(0)
const loading = ref(false)
const query = reactive({ page: 1, page_size: 20, status: '', keyword: '' })
const detailVisible = ref(false)
const testVisible = ref(false)
const current = ref(null)
const testForm = reactive({ title: '手工测试告警', ip: '8.8.8.8', risk_level: 'high', confidence: 90 })

function statusType(s) {
  return ({ processed: 'success', whitelisted: 'warning', failed: 'danger', ignored: 'info' })[s] || 'primary'
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
    ElMessage.success(`告警已接收，生成 ${res.task_count} 个任务`)
    testVisible.value = false
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
