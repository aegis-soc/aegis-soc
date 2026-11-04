<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">IP 黑名单</h2><p class="page-desc">受管攻击 IP，删除时自动生成解封任务；白名单与内网地址禁止加入</p></div>
      <el-button type="primary" :icon="Plus" @click="dialog = true">新增黑名单</el-button>
    </div>
    <div class="filter-bar">
      <el-select v-model="query.status" placeholder="状态" clearable style="width: 140px">
        <el-option v-for="s in ['active','expired','disabled']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-input v-model="query.keyword" placeholder="IP / 备注关键字" clearable style="width: 220px" @keyup.enter="load" />
      <el-button type="primary" @click="load">查询</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe v-loading="loading">
        <el-table-column prop="normalized_value" label="IP / CIDR" min-width="150" class-name="mono" />
        <el-table-column prop="risk_level" label="风险" width="90" />
        <el-table-column prop="confidence" label="置信度" width="90" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }"><el-tag size="small" :type="row.status === 'active' ? 'danger' : 'info'">{{ row.status }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="source_count" label="来源数" width="80" />
        <el-table-column prop="expire_at" label="过期时间" width="170" />
        <el-table-column prop="remark" label="备注" min-width="160" show-overflow-tooltip />
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-popconfirm title="删除将自动生成解封任务，确认？" @confirm="remove(row)">
              <template #reference><el-button link type="danger">删除</el-button></template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>

    <el-dialog v-model="dialog" title="新增 IP 黑名单" width="480px">
      <el-form :model="form" label-width="110px">
        <el-form-item label="IP 地址" required><el-input v-model="form.ioc_value" placeholder="公网 IP 或 CIDR（最大 /16）" /></el-form-item>
        <el-form-item label="置信度"><el-input-number v-model="form.confidence" :min="0" :max="100" /></el-form-item>
        <el-form-item label="风险等级">
          <el-select v-model="form.risk_level" style="width: 100%"><el-option v-for="s in ['critical','high','medium','low']" :key="s" :label="s" :value="s" /></el-select>
        </el-form-item>
        <el-form-item label="封禁时长(秒)"><el-input-number v-model="form.duration_seconds" :min="0" :step="3600" /><span class="text-muted" style="margin-left: 8px; font-size: 11px">0 = 永久</span></el-form-item>
        <el-form-item label="备注"><el-input v-model="form.remark" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="立即下发"><el-switch v-model="form.dispatch" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog = false">取消</el-button><el-button type="primary" @click="submit">提交</el-button></template>
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
const dialog = ref(false)
const query = reactive({ page: 1, page_size: 20, status: '', keyword: '' })
const form = reactive({ ioc_value: '', confidence: 80, risk_level: 'high', duration_seconds: 7200, remark: '', dispatch: true })

async function load() {
  loading.value = true
  try {
    const params = { ...query }
    Object.keys(params).forEach((k) => { if (params[k] === '') delete params[k] })
    const data = await api.iocIps(params)
    rows.value = data.items
    total.value = data.total
  } catch (e) { /* 拦截器已提示 */ } finally { loading.value = false }
}
async function submit() {
  try {
    const data = await api.addIocIp({ ...form, ioc_type: 'IP' })
    ElMessage.success(`已保存，生成 ${data.task_count} 个封禁任务`)
    dialog.value = false
    form.ioc_value = ''
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
async function remove(row) {
  try {
    const data = await api.deleteIocIp(row.id)
    ElMessage.success(`已删除，生成 ${data.unblock_task_count} 个解封任务`)
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
