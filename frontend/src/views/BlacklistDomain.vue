<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">域名黑名单</h2><p class="page-desc">恶意域名 IOC，支持精确 / 子域 / 通配符匹配语义</p></div>
      <div>
        <el-button :icon="Download" @click="doExport">导出 CSV</el-button>
        <el-button :icon="Upload" @click="openImport">批量导入</el-button>
        <el-button type="primary" :icon="Plus" @click="dialog = true">新增域名</el-button>
      </div>
    </div>
    <div class="filter-bar">
      <el-select v-model="query.status" placeholder="状态" clearable style="width: 140px">
        <el-option v-for="s in STATUS_OPTIONS" :key="s.value" :label="s.label" :value="s.value" />
      </el-select>
      <el-select v-model="query.source_type" placeholder="来源" clearable style="width: 130px">
        <el-option v-for="s in SOURCE_OPTIONS" :key="s.value" :label="s.label" :value="s.value" />
      </el-select>
      <el-input v-model="query.keyword" placeholder="域名 / 设备名 / 告警ID" clearable style="width: 240px" @keyup.enter="load" />
      <el-button type="primary" @click="load">查询</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="normalized_value" label="域名" min-width="220" class-name="mono" />
        <el-table-column label="来源" width="120">
          <template #default="{ row }">
            <el-tooltip :content="sourceTooltip(row)" placement="top">
              <el-tag size="small" :type="SOURCE_TAG[row.source_type] || 'info'">{{ SOURCE_LABEL[row.source_type] || row.source_type || '未知' }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column prop="risk_level" label="风险" width="80" />
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tooltip :content="row.reject_reason || statusLabel(row.status)" placement="top">
              <el-tag size="small" :type="STATUS_TAG[row.status] || 'info'">{{ statusLabel(row.status) }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="添加时间" width="160">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="过期时间" width="160">
          <template #default="{ row }">{{ fmt(row.expire_at) || '永久' }}</template>
        </el-table-column>
        <el-table-column prop="remark" label="备注 / 原因" min-width="180" show-overflow-tooltip />
        <el-table-column label="操作" width="90" fixed="right">
          <template #default="{ row }">
            <el-popconfirm title="确认删除该域名黑名单？" @confirm="remove(row)">
              <template #reference><el-button link type="danger">删除</el-button></template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>

    <el-dialog v-model="dialog" title="新增域名黑名单" width="460px">
      <el-form :model="form" label-width="100px">
        <el-form-item label="域名" required><el-input v-model="form.ioc_value" placeholder="evil.example.com 或 *.example.com" /></el-form-item>
        <el-form-item label="置信度"><el-input-number v-model="form.confidence" :min="0" :max="100" /></el-form-item>
        <el-form-item label="备注"><el-input v-model="form.remark" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="立即下发"><el-switch v-model="form.dispatch" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog = false">取消</el-button><el-button type="primary" @click="submit">提交</el-button></template>
    </el-dialog>

    <el-dialog v-model="importDialog" title="批量导入域名黑名单" width="560px">
      <el-alert type="info" :closable="false" style="margin-bottom: 12px"
        title="每行一个域名（支持 *.example.com 通配符），支持备注：evil.com,C2服务器 或 evil.com # C2服务器；# 开头为注释行" />
      <el-form label-width="100px">
        <el-form-item label="粘贴文本">
          <el-input v-model="importText" type="textarea" :rows="7" placeholder="evil.example.com&#10;*.malware.cn,C2 基础设施&#10;# 这是注释" />
        </el-form-item>
        <el-form-item label="或上传文件">
          <input type="file" accept=".txt,.csv,.log" @change="onImportFile" />
          <span v-if="importFile" class="text-muted" style="margin-left: 8px; font-size: 12px">{{ importFile.name }}</span>
        </el-form-item>
        <el-form-item label="备注"><el-input v-model="importForm.remark" placeholder="整批备注（行内备注优先）" /></el-form-item>
        <el-form-item label="立即下发"><el-switch v-model="importForm.dispatch" /></el-form-item>
      </el-form>
      <el-alert v-if="importResult" :type="importResult.errors?.length ? 'warning' : 'success'" :closable="false">
        <p>新增 {{ importResult.created }} 条，已存在跳过 {{ importResult.skipped }} 条，白名单豁免 {{ importResult.whitelisted }} 条，下发任务 {{ importResult.task_count }} 个</p>
        <p v-if="importResult.errors?.length" style="margin-top: 4px; font-size: 12px">
          {{ importResult.errors.slice(0, 10).join('；') }}{{ importResult.errors.length > 10 ? ` 等 ${importResult.errors.length} 条` : '' }}
        </p>
      </el-alert>
      <template #footer>
        <el-button @click="importDialog = false">关闭</el-button>
        <el-button type="primary" :loading="importing" @click="submitImport">导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Download, Plus, Upload } from '@element-plus/icons-vue'
import { api } from '../api'

const rows = ref([])
const total = ref(0)
const dialog = ref(false)
const query = reactive({ page: 1, page_size: 20, status: '', source_type: '', keyword: '' })
const form = reactive({ ioc_value: '', confidence: 80, remark: '', dispatch: true, ioc_type: 'DOMAIN' })

const STATUS_OPTIONS = [
  { value: 'active', label: '已下发' },
  { value: 'rejected', label: '被拦截' },
  { value: 'whitelisted', label: '白名单豁免' },
  { value: 'expired', label: '已过期' },
  { value: 'disabled', label: '已解封' },
]
const STATUS_TAG = { active: 'danger', rejected: 'warning', whitelisted: 'info', expired: 'info', disabled: 'info' }
const STATUS_LABEL = Object.fromEntries(STATUS_OPTIONS.map((s) => [s.value, s.label]))

const SOURCE_OPTIONS = [
  { value: 'IPS', label: 'IPS 入侵防御' },
  { value: 'WAF', label: 'WAF' },
  { value: 'ZTNA', label: '零信任' },
  { value: 'TI', label: '威胁情报' },
  { value: 'NTA', label: '态势感知' },
  { value: 'AV', label: '防病毒' },
  { value: 'FW', label: '防火墙' },
  { value: 'GRAYLOG', label: 'Graylog' },
  { value: 'MANUAL', label: '手工添加' },
  { value: 'API', label: 'API' },
  { value: 'UNKNOWN', label: '未识别' },
]
const SOURCE_LABEL = Object.fromEntries(SOURCE_OPTIONS.map((s) => [s.value, s.label]))
const SOURCE_TAG = { IPS: 'danger', WAF: 'warning', ZTNA: 'primary', TI: 'danger', NTA: 'warning', AV: 'warning', FW: 'primary', MANUAL: 'info', GRAYLOG: 'info', API: 'info' }

function statusLabel(status) {
  return STATUS_LABEL[status] || status
}
function fmt(value) {
  if (!value) return ''
  return String(value).replace('T', ' ').slice(0, 19)
}
function sourceTooltip(row) {
  const parts = [row.source_type || 'UNKNOWN']
  if (row.source_detail) parts.push(row.source_detail)
  if (row.alert_id) parts.push(`告警 ${row.alert_id}`)
  return parts.join(' · ')
}

async function load() {
  const params = { ...query }
  Object.keys(params).forEach((k) => { if (params[k] === '') delete params[k] })
  const data = await api.iocDomains(params)
  rows.value = data.items
  total.value = data.total
}
async function submit() {
  try {
    await api.addIocDomain(form)
    ElMessage.success('域名已加入黑名单')
    dialog.value = false
    form.ioc_value = ''
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
async function remove(row) {
  try { await api.deleteIocDomain(row.id); ElMessage.success('已删除'); load() } catch (e) { /* 拦截器已提示 */ }
}

// ---------------- 批量导入 / 导出 ----------------
const importDialog = ref(false)
const importing = ref(false)
const importText = ref('')
const importFile = ref(null)
const importResult = ref(null)
const importForm = reactive({ dispatch: true, remark: '' })

function openImport() {
  importText.value = ''
  importFile.value = null
  importResult.value = null
  importDialog.value = true
}
function onImportFile(e) {
  importFile.value = e.target.files?.[0] || null
}
async function submitImport() {
  if (!importText.value.trim() && !importFile.value) {
    ElMessage.warning('请粘贴文本或选择文件')
    return
  }
  importing.value = true
  try {
    const fd = new FormData()
    if (importFile.value) fd.append('file', importFile.value)
    if (importText.value.trim()) fd.append('text', importText.value)
    fd.append('dispatch', String(importForm.dispatch))
    if (importForm.remark.trim()) fd.append('remark', importForm.remark.trim())
    const data = await api.importIocDomains(fd)
    importResult.value = data
    ElMessage.success(`导入完成：新增 ${data.created} 条`)
    load()
  } catch (e) { /* 拦截器已提示 */ } finally { importing.value = false }
}
async function doExport() {
  try {
    const params = { ...query }
    delete params.page
    delete params.page_size
    Object.keys(params).forEach((k) => { if (params[k] === '') delete params[k] })
    const blob = await api.exportIocDomains(params)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `blacklist-domain-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) { ElMessage.error('导出失败') }
}
onMounted(load)
</script>
