<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">{{ t('blacklist.ip.title') }}</h2><p class="page-desc">{{ t('blacklist.ip.desc') }}</p></div>
      <div>
        <el-button :icon="Download" @click="doExport">{{ t('blacklist.common.exportCsv') }}</el-button>
        <el-button :icon="Upload" @click="openImport">{{ t('blacklist.common.import') }}</el-button>
        <el-button type="primary" :icon="Plus" @click="dialog = true">{{ t('blacklist.ip.add') }}</el-button>
      </div>
    </div>
    <div class="filter-bar">
      <el-select v-model="query.status" :placeholder="t('blacklist.common.statusPlaceholder')" clearable style="width: 150px">
        <el-option v-for="s in STATUS_VALUES" :key="s" :label="statusLabel(s)" :value="s" />
      </el-select>
      <el-select v-model="query.source_type" :placeholder="t('blacklist.common.sourcePlaceholder')" clearable style="width: 150px">
        <el-option v-for="s in SOURCE_VALUES" :key="s" :label="sourceLabel(s)" :value="s" />
      </el-select>
      <el-select v-model="query.country" :placeholder="t('blacklist.ip.countryPlaceholder')" clearable filterable allow-create default-first-option style="width: 160px">
        <el-option v-for="c in COUNTRY_OPTIONS" :key="c" :label="countryLabel(c)" :value="c" />
      </el-select>
      <el-input v-model="query.keyword" :placeholder="t('blacklist.common.keywordIp')" clearable style="width: 260px" @keyup.enter="load" />
      <el-button type="primary" @click="load">{{ t('common.action.search') }}</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe v-loading="loading">
        <el-table-column prop="normalized_value" :label="t('blacklist.ip.col.ip')" min-width="140" class-name="mono" fixed />
        <el-table-column :label="t('blacklist.ip.col.country')" width="130">
          <template #default="{ row }">
            <span v-if="!row.geo_country" class="text-muted">-</span>
            <el-tag v-else size="small" :type="row.geo_country === '中国' ? 'danger' : 'info'" effect="plain">{{ countryLabel(row.geo_country) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('blacklist.ip.col.region')" min-width="150">
          <template #default="{ row }">
            <span v-if="!row.geo_region" class="text-muted">-</span>
            <el-tooltip v-else :content="geoTitle(row)" placement="top">
              <span>{{ row.geo_region }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column :label="t('blacklist.ip.col.source')" width="130">
          <template #default="{ row }">
            <el-tooltip :content="sourceTooltip(row)" placement="top">
              <el-tag size="small" :type="SOURCE_TAG[row.source_type] || 'info'">{{ sourceLabel(row.source_type) }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column :label="t('blacklist.ip.col.status')" width="120">
          <template #default="{ row }">
            <el-tooltip :content="row.reject_reason || statusLabel(row.status)" placement="top">
              <el-tag size="small" :type="STATUS_TAG[row.status] || 'info'">{{ statusLabel(row.status) }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column prop="risk_level" :label="t('blacklist.ip.col.risk')" width="90">
          <template #default="{ row }">{{ riskLabel(row.risk_level) }}</template>
        </el-table-column>
        <el-table-column prop="confidence" :label="t('blacklist.ip.col.confidence')" width="90" />
        <el-table-column :label="t('blacklist.ip.col.createdAt')" width="160">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column :label="t('blacklist.ip.col.expireAt')" width="160">
          <template #default="{ row }">{{ fmt(row.expire_at) || t('blacklist.common.permanent') }}</template>
        </el-table-column>
        <el-table-column prop="remark" :label="t('blacklist.ip.col.remark')" min-width="200" show-overflow-tooltip />
        <el-table-column :label="t('blacklist.ip.col.actions')" width="100" fixed="right">
          <template #default="{ row }">
            <el-popconfirm :title="row.status === 'active' ? t('blacklist.ip.confirmUnblock') : t('blacklist.ip.confirmDeleteLog')" @confirm="remove(row)">
              <template #reference><el-button link type="danger">{{ t('common.action.delete') }}</el-button></template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>

    <el-dialog v-model="dialog" :title="t('blacklist.ip.dialog.title')" width="480px">
      <el-form :model="form" label-width="120px">
        <el-form-item :label="t('blacklist.ip.dialog.ip')" required><el-input v-model="form.ioc_value" :placeholder="t('blacklist.ip.dialog.ipPlaceholder')" /></el-form-item>
        <el-form-item :label="t('blacklist.common.confidence')"><el-input-number v-model="form.confidence" :min="0" :max="100" /></el-form-item>
        <el-form-item :label="t('blacklist.common.riskLevel')">
          <el-select v-model="form.risk_level" style="width: 100%">
            <el-option v-for="s in RISK_VALUES" :key="s" :label="riskLabel(s)" :value="s" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('blacklist.common.duration')">
          <el-input-number v-model="form.duration_seconds" :min="0" :step="3600" />
          <span class="text-muted" style="margin-left: 8px; font-size: 11px">{{ t('blacklist.common.durationHint') }}</span>
        </el-form-item>
        <el-form-item :label="t('blacklist.common.remark')"><el-input v-model="form.remark" type="textarea" :rows="2" /></el-form-item>
        <el-form-item :label="t('blacklist.common.dispatch')"><el-switch v-model="form.dispatch" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog = false">{{ t('common.action.cancel') }}</el-button><el-button type="primary" @click="submit">{{ t('blacklist.common.submit') }}</el-button></template>
    </el-dialog>

    <el-dialog v-model="importDialog" :title="t('blacklist.ip.importTitle')" width="560px">
      <el-alert type="info" :closable="false" style="margin-bottom: 12px" :title="t('blacklist.ip.importHint')" />
      <el-form label-width="110px">
        <el-form-item :label="t('blacklist.common.pasteText')">
          <el-input v-model="importText" type="textarea" :rows="7" :placeholder="t('blacklist.ip.importPlaceholder')" />
        </el-form-item>
        <el-form-item :label="t('blacklist.common.orFile')">
          <input type="file" accept=".txt,.csv,.log" @change="onImportFile" />
          <span v-if="importFile" class="text-muted" style="margin-left: 8px; font-size: 12px">{{ importFile.name }}</span>
        </el-form-item>
        <el-form-item :label="t('blacklist.common.duration')">
          <el-input-number v-model="importForm.duration_seconds" :min="0" :step="3600" />
          <span class="text-muted" style="margin-left: 8px; font-size: 11px">{{ t('blacklist.common.durationHint') }}</span>
        </el-form-item>
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
const loading = ref(false)
const dialog = ref(false)
const query = reactive({ page: 1, page_size: 20, status: '', source_type: '', country: '', keyword: '' })
const form = reactive({ ioc_value: '', confidence: 80, risk_level: 'high', duration_seconds: 7200, remark: '', dispatch: true })

const STATUS_VALUES = ['active', 'rejected', 'whitelisted', 'expired', 'disabled']
const STATUS_TAG = { active: 'danger', rejected: 'warning', whitelisted: 'info', expired: 'info', disabled: 'info' }
const SOURCE_VALUES = ['IPS', 'WAF', 'ZTNA', 'TI', 'NTA', 'AV', 'FW', 'GRAYLOG', 'MANUAL', 'API', 'UNKNOWN']
const SOURCE_TAG = { IPS: 'danger', WAF: 'warning', ZTNA: 'primary', TI: 'danger', NTA: 'warning', AV: 'warning', FW: 'primary', MANUAL: 'info', GRAYLOG: 'info', API: 'info' }
const RISK_VALUES = ['critical', 'high', 'medium', 'low']

function pick(namespace, value) {
  if (!value) return '-'
  const key = `${namespace}.${value}`
  return te(key) ? t(key) : value
}
const statusLabel = (v) => pick('blacklist.status', v)
const sourceLabel = (v) => pick('blacklist.source', v || 'UNKNOWN')
const riskLabel = (v) => pick('enums.risk', v)
// 国家名是 ip2region 写入数据库的中文原值，这里只做显示映射，值本身不改
const countryLabel = (v) => pick('blacklist.country', v)

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
function geoTitle(row) {
  const parts = [countryLabel(row.geo_country), row.geo_region].filter(Boolean)
  if (row.geo_isp) parts.push(row.geo_isp)
  return parts.join(' · ')
}

// 内置常用国家选项（值仍是中文，保证与库内数据、后端过滤一致）
const COUNTRY_OPTIONS = [
  '内网', '保留地址', '中国', '中国香港', '中国澳门', '中国台湾',
  '美国', '俄罗斯', '日本', '韩国', '印度', '越南', '新加坡',
  '德国', '法国', '英国', '荷兰', '巴西', '加拿大', '澳大利亚', '印度尼西亚',
]

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
    ElMessage.success(t('blacklist.ip.saved', { n: data.task_count }))
    dialog.value = false
    form.ioc_value = ''
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
async function remove(row) {
  try {
    const data = await api.deleteIocIp(row.id)
    ElMessage.success(t('blacklist.ip.deleted', { n: data.unblock_task_count }))
    load()
  } catch (e) { /* 拦截器已提示 */ }
}

// ---------------- 批量导入 / 导出 ----------------
const importDialog = ref(false)
const importing = ref(false)
const importText = ref('')
const importFile = ref(null)
const importResult = ref(null)
const importForm = reactive({ dispatch: true, duration_seconds: 7200 })

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
    fd.append('duration_seconds', String(importForm.duration_seconds || 0))
    const data = await api.importIocIps(fd)
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
    const blob = await api.exportIocIps(params)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `blacklist-ip-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) { ElMessage.error(t('blacklist.common.exportFailed')) }
}
onMounted(load)
</script>
