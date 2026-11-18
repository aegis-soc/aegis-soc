<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">{{ t('blacklist.domain.title') }}</h2><p class="page-desc">{{ t('blacklist.domain.desc') }}</p></div>
      <div>
        <el-button :icon="Download" @click="doExport">{{ t('blacklist.common.exportCsv') }}</el-button>
        <el-button :icon="Upload" @click="openImport">{{ t('blacklist.common.import') }}</el-button>
        <el-button type="primary" :icon="Plus" @click="dialog = true">{{ t('blacklist.domain.add') }}</el-button>
      </div>
    </div>
    <div class="filter-bar">
      <el-select v-model="query.status" :placeholder="t('blacklist.common.statusPlaceholder')" clearable style="width: 150px">
        <el-option v-for="s in STATUS_VALUES" :key="s" :label="statusLabel(s)" :value="s" />
      </el-select>
      <el-select v-model="query.source_type" :placeholder="t('blacklist.common.sourcePlaceholder')" clearable style="width: 150px">
        <el-option v-for="s in SOURCE_VALUES" :key="s" :label="sourceLabel(s)" :value="s" />
      </el-select>
      <el-input v-model="query.keyword" :placeholder="t('blacklist.common.keywordDomain')" clearable style="width: 260px" @keyup.enter="load" />
      <el-button type="primary" @click="load">{{ t('common.action.search') }}</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="normalized_value" :label="t('blacklist.domain.col.domain')" min-width="220" class-name="mono" />
        <el-table-column :label="t('blacklist.domain.col.source')" width="130">
          <template #default="{ row }">
            <el-tooltip :content="sourceTooltip(row)" placement="top">
              <el-tag size="small" :type="SOURCE_TAG[row.source_type] || 'info'">{{ sourceLabel(row.source_type) }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column prop="risk_level" :label="t('blacklist.domain.col.risk')" width="90">
          <template #default="{ row }">{{ riskLabel(row.risk_level) }}</template>
        </el-table-column>
        <el-table-column :label="t('blacklist.domain.col.status')" width="120">
          <template #default="{ row }">
            <el-tooltip :content="row.reject_reason || statusLabel(row.status)" placement="top">
              <el-tag size="small" :type="STATUS_TAG[row.status] || 'info'">{{ statusLabel(row.status) }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column :label="t('blacklist.domain.col.createdAt')" width="160">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column :label="t('blacklist.domain.col.expireAt')" width="160">
          <template #default="{ row }">{{ fmt(row.expire_at) || t('blacklist.common.permanent') }}</template>
        </el-table-column>
        <el-table-column prop="remark" :label="t('blacklist.domain.col.remark')" min-width="180" show-overflow-tooltip />
        <el-table-column :label="t('blacklist.domain.col.actions')" width="90" fixed="right">
          <template #default="{ row }">
            <el-popconfirm :title="t('blacklist.domain.confirmDelete')" @confirm="remove(row)">
              <template #reference><el-button link type="danger">{{ t('common.action.delete') }}</el-button></template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>

    <el-dialog v-model="dialog" :title="t('blacklist.domain.dialog.title')" width="460px">
      <el-form :model="form" label-width="110px">
        <el-form-item :label="t('blacklist.domain.dialog.domain')" required><el-input v-model="form.ioc_value" :placeholder="t('blacklist.domain.dialog.placeholder')" /></el-form-item>
        <el-form-item :label="t('blacklist.common.confidence')"><el-input-number v-model="form.confidence" :min="0" :max="100" /></el-form-item>
        <el-form-item :label="t('blacklist.common.remark')"><el-input v-model="form.remark" type="textarea" :rows="2" /></el-form-item>
        <el-form-item :label="t('blacklist.common.dispatch')"><el-switch v-model="form.dispatch" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog = false">{{ t('common.action.cancel') }}</el-button><el-button type="primary" @click="submit">{{ t('blacklist.common.submit') }}</el-button></template>
    </el-dialog>

    <el-dialog v-model="importDialog" :title="t('blacklist.domain.importTitle')" width="560px">
      <el-alert type="info" :closable="false" style="margin-bottom: 12px" :title="t('blacklist.domain.importHint')" />
      <el-form label-width="110px">
        <el-form-item :label="t('blacklist.common.pasteText')">
          <el-input v-model="importText" type="textarea" :rows="7" :placeholder="t('blacklist.domain.importPlaceholder')" />
        </el-form-item>
        <el-form-item :label="t('blacklist.common.orFile')">
          <input type="file" accept=".txt,.csv,.log" @change="onImportFile" />
          <span v-if="importFile" class="text-muted" style="margin-left: 8px; font-size: 12px">{{ importFile.name }}</span>
        </el-form-item>
        <el-form-item :label="t('blacklist.common.remark')"><el-input v-model="importForm.remark" :placeholder="t('blacklist.domain.importRemark')" /></el-form-item>
        <el-form-item :label="t('blacklist.common.dispatch')"><el-switch v-model="importForm.dispatch" /></el-form-item>
      </el-form>
      <el-alert v-if="importResult" :type="importResult.errors?.length ? 'warning' : 'success'" :closable="false">
        <p>{{ t('blacklist.common.importSummary', { created: importResult.created, skipped: importResult.skipped, whitelisted: importResult.whitelisted, tasks: importResult.task_count }) }}</p>
        <p v-if="importResult.errors?.length" style="margin-top: 4px; font-size: 12px">
          {{ importResult.errors.slice(0, 10).join('; ') }}{{ importResult.errors.length > 10 ? ' ' + t('blacklist.common.importMore', { n: importResult.errors.length }) : '' }}
        </p>
      </el-alert>
      <template #footer>
        <el-button @click="importDialog = false">{{ t('blacklist.common.close') }}</el-button>
        <el-button type="primary" :loading="importing" @click="submitImport">{{ t('common.action.import') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Download, Plus, Upload } from '@element-plus/icons-vue'
import { api } from '../api'

const { t, te } = useI18n()
const rows = ref([])
const total = ref(0)
const dialog = ref(false)
const query = reactive({ page: 1, page_size: 20, status: '', source_type: '', keyword: '' })
const form = reactive({ ioc_value: '', confidence: 80, remark: '', dispatch: true, ioc_type: 'DOMAIN' })

const STATUS_VALUES = ['active', 'rejected', 'whitelisted', 'expired', 'disabled']
const STATUS_TAG = { active: 'danger', rejected: 'warning', whitelisted: 'info', expired: 'info', disabled: 'info' }
const SOURCE_VALUES = ['IPS', 'WAF', 'ZTNA', 'TI', 'NTA', 'AV', 'FW', 'GRAYLOG', 'MANUAL', 'API', 'UNKNOWN']
const SOURCE_TAG = { IPS: 'danger', WAF: 'warning', ZTNA: 'primary', TI: 'danger', NTA: 'warning', AV: 'warning', FW: 'primary', MANUAL: 'info', GRAYLOG: 'info', API: 'info' }

function pick(namespace, value) {
  if (!value) return '-'
  const key = `${namespace}.${value}`
  return te(key) ? t(key) : value
}
const statusLabel = (v) => pick('blacklist.status', v)
const sourceLabel = (v) => pick('blacklist.source', v || 'UNKNOWN')
const riskLabel = (v) => pick('enums.risk', v)

function fmt(value) {
  if (!value) return ''
  return String(value).replace('T', ' ').slice(0, 19)
}
function sourceTooltip(row) {
  const parts = [sourceLabel(row.source_type)]
  if (row.source_detail) parts.push(row.source_detail)
  if (row.alert_id) parts.push(t('blacklist.common.alertRef', { id: row.alert_id }))
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
    ElMessage.success(t('blacklist.domain.saved'))
    dialog.value = false
    form.ioc_value = ''
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
async function remove(row) {
  try { await api.deleteIocDomain(row.id); ElMessage.success(t('blacklist.domain.deleted')); load() } catch (e) { /* 拦截器已提示 */ }
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
    ElMessage.warning(t('blacklist.common.needInput'))
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
    ElMessage.success(t('blacklist.common.imported', { n: data.created }))
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
  } catch (e) { ElMessage.error(t('blacklist.common.exportFailed')) }
}
onMounted(load)
</script>
