<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">IP 白名单</h2><p class="page-desc">受保护地址 / 网段，命中即豁免封禁；新增会自动解封网段内已下发的黑名单</p></div>
      <div>
        <el-button :icon="Upload" @click="importVisible = true">批量导入</el-button>
        <el-button type="primary" :icon="Plus" @click="dialog = true">新增白名单</el-button>
      </div>
    </div>
    <div class="filter-bar">
      <el-input v-model="checkIp" placeholder="输入 IP 检查是否命中白名单" style="width: 260px" />
      <el-button @click="doCheck">检查命中</el-button>
      <el-tag v-if="checkResult" :type="checkResult.whitelisted ? 'warning' : 'success'" effect="light">
        {{ checkResult.whitelisted ? `已保护：${checkResult.matched}` : '未命中，可自动封禁' }}
      </el-tag>
      <el-input v-model="query.keyword" placeholder="地址关键字" clearable style="width: 200px" @keyup.enter="load" />
      <el-button type="primary" @click="load">查询</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="cidr" label="地址 / 网段" min-width="180" class-name="mono">
          <template #default="{ row }">{{ row.cidr || row.ip_value }}</template>
        </el-table-column>
        <el-table-column prop="prefix_len" label="掩码" width="90" />
        <el-table-column prop="cidr_flag" label="类型" width="100">
          <template #default="{ row }">{{ row.cidr_flag ? 'CIDR 网段' : '单 IP' }}</template>
        </el-table-column>
        <el-table-column prop="remark" label="备注" min-width="200" show-overflow-tooltip />
        <el-table-column prop="created_by" label="创建人" width="110" />
        <el-table-column label="操作" width="90" fixed="right">
          <template #default="{ row }">
            <el-popconfirm title="删除后该地址将不再受保护，确认？" @confirm="remove(row)">
              <template #reference><el-button link type="danger">删除</el-button></template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>

    <el-dialog v-model="dialog" title="新增白名单" width="460px">
      <el-form :model="form" label-width="120px">
        <el-form-item label="IP / CIDR" required><el-input v-model="form.ip_value" placeholder="如 203.0.113.0/24" /></el-form-item>
        <el-form-item label="备注"><el-input v-model="form.remark" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="自动解封已有"><el-switch v-model="form.unblock_existing" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog = false">取消</el-button><el-button type="primary" @click="submit">提交</el-button></template>
    </el-dialog>

    <el-dialog v-model="importVisible" title="批量导入白名单" width="520px">
      <p class="text-muted" style="font-size: 12px">每行一个 IP 或 CIDR，支持 # 行内注释；最大允许 /8 网段。</p>
      <el-input v-model="importText" type="textarea" :rows="8" placeholder="203.0.113.0/24&#10;198.51.100.10 # 示例地址" />
      <template #footer><el-button @click="importVisible = false">取消</el-button><el-button type="primary" @click="doImport">导入</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus, Upload } from '@element-plus/icons-vue'
import { api } from '../api'

const rows = ref([])
const total = ref(0)
const dialog = ref(false)
const importVisible = ref(false)
const importText = ref('')
const checkIp = ref('')
const checkResult = ref(null)
const query = reactive({ page: 1, page_size: 20, keyword: '' })
const form = reactive({ ip_value: '', remark: '', unblock_existing: true })

async function load() {
  const params = { ...query }
  if (!params.keyword) delete params.keyword
  const data = await api.whitelist(params)
  rows.value = data.items
  total.value = data.total
}
async function doCheck() {
  if (!checkIp.value) return
  try { checkResult.value = await api.checkWhitelist(checkIp.value) } catch (e) { /* 拦截器已提示 */ }
}
async function submit() {
  try {
    const data = await api.addWhitelist(form)
    ElMessage.success(`已保存，自动解封 ${data.unblock_task_count} 个任务`)
    dialog.value = false
    form.ip_value = ''
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
async function doImport() {
  try {
    const data = await api.importWhitelist(importText.value)
    ElMessage.success(`导入成功 ${data.created} 条，跳过 ${data.skipped} 条，错误 ${data.errors.length} 条`)
    importVisible.value = false
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
async function remove(row) {
  try { await api.deleteWhitelist(row.id); ElMessage.success('已删除'); load() } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
