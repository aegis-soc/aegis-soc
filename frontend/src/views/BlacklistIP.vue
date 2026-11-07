<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">IP 黑名单</h2><p class="page-desc">同一 IP 多次命中按流水记录保存，不合并；被拦截的 IOC 也会留痕，状态为 rejected / whitelisted；国家/地区由 ip2region 离线库在写入时记录</p></div>
      <div>
        <el-button :icon="Download" @click="doExport">导出 CSV</el-button>
        <el-button :icon="Upload" @click="openImport">批量导入</el-button>
        <el-button type="primary" :icon="Plus" @click="dialog = true">新增黑名单</el-button>
      </div>
    </div>
    <div class="filter-bar">
      <el-select v-model="query.status" placeholder="状态" clearable style="width: 140px">
        <el-option v-for="s in STATUS_OPTIONS" :key="s.value" :label="s.label" :value="s.value" />
      </el-select>
      <el-select v-model="query.source_type" placeholder="来源" clearable style="width: 130px">
        <el-option v-for="s in SOURCE_OPTIONS" :key="s.value" :label="s.label" :value="s.value" />
      </el-select>
      <el-select v-model="query.country" placeholder="国家/地区" clearable filterable allow-create default-first-option style="width: 150px">
        <el-option v-for="c in COUNTRY_OPTIONS" :key="c" :label="c" :value="c" />
      </el-select>
      <el-input v-model="query.keyword" placeholder="IP / 归属地 / 设备名 / 告警ID" clearable style="width: 240px" @keyup.enter="load" />
      <el-button type="primary" @click="load">查询</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe v-loading="loading">
        <el-table-column prop="normalized_value" label="IP / CIDR" min-width="140" class-name="mono" fixed />
        <el-table-column label="国家" width="110">
          <template #default="{ row }">
            <span v-if="!row.geo_country" class="text-muted">-</span>
            <el-tag v-else size="small" :type="row.geo_country === '中国' ? 'danger' : 'info'" effect="plain">{{ row.geo_country }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="地区" min-width="150">
          <template #default="{ row }">
            <span v-if="!row.geo_region" class="text-muted">-</span>
            <el-tooltip v-else :content="geoTitle(row)" placement="top">
              <span>{{ row.geo_region }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="来源" width="120">
          <template #default="{ row }">
            <el-tooltip :content="sourceTooltip(row)" placement="top">
              <el-tag size="small" :type="SOURCE_TAG[row.source_type] || 'info'">{{ SOURCE_LABEL[row.source_type] || row.source_type || '未知' }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tooltip :content="row.reject_reason || statusLabel(row.status)" placement="top">
              <el-tag size="small" :type="STATUS_TAG[row.status] || 'info'">{{ statusLabel(row.status) }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column prop="risk_level" label="风险" width="80" />
        <el-table-column prop="confidence" label="置信度" width="80" />
        <el-table-column label="添加时间" width="160">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="过期时间" width="160">
          <template #default="{ row }">{{ fmt(row.expire_at) || '永久' }}</template>
        </el-table-column>
        <el-table-column prop="remark" label="备注 / 原因" min-width="200" show-overflow-tooltip />
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-popconfirm :title="row.status === 'active' ? '删除将自动生成解封任务，确认？' : '删除这条留痕记录？'" @confirm="remove(row)">
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

    <el-dialog v-model="importDialog" title="批量导入 IP 黑名单" width="560px">
      <el-alert type="info" :closable="false" style="margin-bottom: 12px"
        title="每行一个公网 IP 或 CIDR（最大 /16），支持备注：1.2.3.4,攻击源 或 1.2.3.4 # 攻击源；# 开头为注释行" />
      <el-form label-width="100px">
        <el-form-item label="粘贴文本">
          <el-input v-model="importText" type="textarea" :rows="7" placeholder="1.2.3.4&#10;5.6.7.0/24,扫描源&#10;# 这是注释" />
        </el-form-item>
        <el-form-item label="或上传文件">
          <input type="file" accept=".txt,.csv,.log" @change="onImportFile" />
          <span v-if="importFile" class="text-muted" style="margin-left: 8px; font-size: 12px">{{ importFile.name }}</span>
        </el-form-item>
        <el-form-item label="封禁时长(秒)"><el-input-number v-model="importForm.duration_seconds" :min="0" :step="3600" /><span class="text-muted" style="margin-left: 8px; font-size: 11px">0 = 永久</span></el-form-item>
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
const loading = ref(false)
const dialog = ref(false)
const query = reactive({ page: 1, page_size: 20, status: '', source_type: '', country: '', keyword: '' })
const form = reactive({ ioc_value: '', confidence: 80, risk_level: 'high', duration_seconds: 7200, remark: '', dispatch: true })

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

function geoTitle(row) {
  const parts = [row.geo_country, row.geo_region].filter(Boolean)
  if (row.geo_isp) parts.push(row.geo_isp)
  return parts.join(' · ')
}

// 内置常用国家选项（可输入任意国家名过滤）；归属地不需要独立接口，
// 由列表数据 + 离线库直接支撑
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
    ElMessage.warning('请粘贴文本或选择文件')
    return
  }
  importing.value = true
  try {
    const fd = new FormData()
    if (importFile.value) fd.append('file', importFile.value)
    if (importText.value.trim()) fd.append('text', importText.value)
    fd.append('dispatch', String(importForm.dispatch))
    fd.append('duration_seconds', String(importForm.duration_seconds || 0) )
    const data = await api.importIocIps(fd)
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
    const blob = await api.exportIocIps(params)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `blacklist-ip-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) { ElMessage.error('导出失败') }
}
onMounted(load)
</script>
