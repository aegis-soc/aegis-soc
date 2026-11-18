<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h2 class="page-title">{{ t('patrol.title') }}</h2>
        <p class="page-desc">{{ t('patrol.desc') }}</p>
      </div>
      <div style="display: flex; gap: 8px">
        <el-button :icon="Setting" @click="openConfig">{{ t('patrol.config') }}</el-button>
        <el-button :icon="Connection" :loading="mcpLoading" @click="testMcp">{{ t('patrol.connectivity') }}</el-button>
        <el-button type="primary" :icon="VideoPlay" :loading="running" @click="doRun">{{ t('patrol.runNow') }}</el-button>
      </div>
    </div>

    <el-alert
      v-if="!run" type="info" show-icon :closable="false"
      :title="t('patrol.empty.title')"
      :description="t('patrol.empty.desc')"
      style="margin-bottom: 16px"
    />
    <el-alert
      v-else-if="run.status !== 'ok'" :type="run.status === 'skipped' ? 'warning' : 'error'"
      show-icon :closable="false" :title="statusText(run.status)"
      :description="run.error || t('patrol.partial')" style="margin-bottom: 16px"
    />

    <template v-if="run">
      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-label">{{ t('patrol.stat.window') }}</div>
          <div class="stat-value" style="font-size: 15px">{{ fmtShort(run.window_start) }} → {{ fmtShort(run.window_end) }}</div>
          <div class="stat-hint">{{ t('patrol.stat.overlapHint', { n: summary.window?.overlap_seconds ?? 0 }) }}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">{{ t('patrol.stat.fetched') }}</div>
          <div class="stat-value">{{ run.fetched }}</div>
          <div class="stat-hint">{{ t('patrol.stat.streamsHint', { n: configuredStreams, ms: run.duration_ms }) }}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">{{ t('patrol.stat.candidates') }}</div>
          <div class="stat-value">{{ run.candidate_count }}</div>
          <div class="stat-hint">{{ t('patrol.stat.ignoredHint', { n: summary.ignored_non_public ?? 0 }) }}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">{{ t('patrol.stat.wouldBlock') }}</div>
          <div class="stat-value" :style="{ color: run.would_block ? 'var(--el-color-danger)' : undefined }">{{ run.would_block }}</div>
          <div class="stat-hint">{{ t('patrol.stat.wouldBlockHint') }}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">{{ t('patrol.stat.blocked') }}</div>
          <div class="stat-value">0</div>
          <div class="stat-hint">{{ t('patrol.stat.blockedHint') }}</div>
        </div>
      </div>

      <div class="table-card" style="margin-bottom: 16px">
        <div class="card-title">{{ t('patrol.streams.title') }}</div>
        <div class="stream-row">
          <div v-for="s in summary.streams || []" :key="s.name" class="stream-chip" :class="{ 'stream-bad': s.error }">
            <span class="stream-name">{{ s.name }}</span>
            <span class="stream-meta">{{ s.error ? t('patrol.streams.readFailed') : s.skipped ? s.skipped : t('patrol.streams.count', { n: s.fetched }) }}</span>
            <el-tooltip v-if="s.error" :content="s.error" placement="top">
              <el-icon class="stream-err"><Warning /></el-icon>
            </el-tooltip>
          </div>
          <span v-if="!(summary.streams || []).length" class="text-muted">{{ t('patrol.streams.none') }}</span>
        </div>
        <div v-if="(summary.rules || []).length" class="rule-row">
          <span class="text-muted" style="font-size: 12px">{{ t('patrol.streams.hitRules') }}</span>
          <el-tag v-for="r in summary.rules" :key="r.key" size="small" :type="ruleType(r.key)" effect="plain">
            {{ r.name }} × {{ r.count }}
          </el-tag>
        </div>
      </div>

      <div class="table-card">
        <div class="card-title">{{ t('patrol.candidates.title') }}</div>
        <el-table :data="run.candidates" v-loading="loading" size="small" :empty-text="t('patrol.candidates.empty')">
          <el-table-column prop="ip_value" :label="t('patrol.col.ip')" width="150">
            <template #default="{ row }"><span class="mono">{{ row.ip_value }}</span></template>
          </el-table-column>
          <el-table-column prop="streams" :label="t('patrol.col.streams')" width="120">
            <template #default="{ row }">
              <el-tag v-for="s in (row.streams || '').split(',').filter(Boolean)" :key="s" size="small" style="margin-right: 4px">{{ s }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="hits" :label="t('patrol.col.hits')" width="80" align="right" />
          <el-table-column :label="t('patrol.col.severity')" width="100">
            <template #default="{ row }">
              <el-rate :model-value="row.severity" disabled :max="5" size="small" />
            </template>
          </el-table-column>
          <el-table-column :label="t('patrol.col.reason')" min-width="240">
            <template #default="{ row }">
              <el-tag v-for="r in row.rules || []" :key="r.key" size="small" :type="ruleType(r.key)" style="margin: 2px 4px 2px 0">
                {{ r.name }}<span v-if="r.count > 1"> ×{{ r.count }}</span>
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="t('patrol.col.decision')" width="160">
            <template #default="{ row }">
              <el-tooltip :content="row.decision_reason || ''" placement="top">
                <el-tag size="small" :type="decisionType(row.decision)">{{ decisionText(row.decision) }}</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column :label="t('patrol.col.lastSeen')" width="160">
            <template #default="{ row }"><span class="mono text-muted">{{ fmtTime(row.last_seen) }}</span></template>
          </el-table-column>
        </el-table>
      </div>
    </template>

    <div class="table-card" style="margin-top: 16px">
      <div class="card-title">{{ t('patrol.history.title') }}</div>
      <el-table :data="runs" v-loading="loading" size="small" :empty-text="t('patrol.history.empty')">
        <el-table-column :label="t('patrol.col.time')" width="170">
          <template #default="{ row }"><span class="mono">{{ fmtTime(row.created_at) }}</span></template>
        </el-table-column>
        <el-table-column :label="t('patrol.col.status')" width="120">
          <template #default="{ row }">
            <el-tag size="small" :type="row.status === 'ok' ? 'success' : row.status === 'skipped' ? 'info' : row.status === 'degraded' ? 'warning' : 'danger'">
              {{ statusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('patrol.col.window')" min-width="180">
          <template #default="{ row }"><span class="mono text-muted">{{ fmtShort(row.window_start) }} → {{ fmtShort(row.window_end) }}</span></template>
        </el-table-column>
        <el-table-column prop="fetched" :label="t('patrol.col.logs')" width="90" align="right" />
        <el-table-column prop="candidate_count" :label="t('patrol.col.candidateCount')" width="100" align="right" />
        <el-table-column prop="would_block" :label="t('patrol.col.wouldBlock')" width="90" align="right" />
        <el-table-column prop="duration_ms" :label="t('patrol.col.duration')" width="110" align="right" />
        <el-table-column :label="t('patrol.col.actions')" width="90">
          <template #default="{ row }">
            <el-button link type="primary" @click="openDetail(row)">{{ t('patrol.history.view') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="pager">
        <el-pagination layout="total, prev, pager, next" :total="total" :page-size="10"
                       :current-page="page" @current-change="(p) => { page = p; loadRuns() }" />
      </div>
    </div>

    <el-dialog v-model="mcpVisible" :title="t('patrol.mcp.title')" width="720px">
      <template v-if="mcpInfo">
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item :label="t('patrol.mcp.server')">{{ mcpInfo.server?.name || '—' }} <span class="text-muted">{{ mcpInfo.server?.version || '' }}</span></el-descriptions-item>
          <el-descriptions-item :label="t('patrol.mcp.protocol')">{{ mcpInfo.protocol_version || '—' }}</el-descriptions-item>
          <el-descriptions-item :label="t('patrol.mcp.transport')">
            <el-tag size="small" :type="mcpInfo.transport === 'sse' ? 'warning' : 'success'">{{ mcpInfo.transport || '—' }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="t('patrol.mcp.auth')">
            <el-tag size="small" type="info">{{ mcpInfo.auth || '—' }}</el-tag>
            <span class="mono text-muted" style="margin-left: 6px">{{ mcpInfo.token_hint || t('patrol.mcp.noToken') }}</span>
          </el-descriptions-item>
          <el-descriptions-item :label="t('patrol.mcp.url')" :span="2"><span class="mono">{{ mcpInfo.url }}</span></el-descriptions-item>
        </el-descriptions>

        <div class="detail-block">
          <div class="detail-label">{{ t('patrol.mcp.tools', { n: (mcpInfo.tools || []).length }) }}</div>
          <div class="stream-row">
            <el-tag v-for="tool in mcpInfo.tools" :key="tool.name" size="small" effect="plain">{{ tool.name }}</el-tag>
          </div>
        </div>

        <div class="detail-block">
          <div class="detail-label">{{ t('patrol.mcp.streamList') }}</div>
          <el-table :data="mcpInfo.streams || []" size="small" max-height="240">
            <el-table-column :label="t('patrol.mcp.streamId')" width="300">
              <template #default="{ row }">
                <span class="mono clickable" :title="t('patrol.mcp.copyHint')" @click="copyStream(row.id)">{{ row.id }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="title" :label="t('patrol.mcp.streamTitle')" />
            <el-table-column :label="t('patrol.mcp.suggested')" width="120">
              <template #default="{ row }">
                <el-tag v-if="row.suggested" size="small" type="success">{{ row.suggested }}</el-tag>
                <span v-else class="text-muted">—</span>
              </template>
            </el-table-column>
          </el-table>
          <div v-if="(mcpInfo.streams || []).length === 0" class="text-muted" style="font-size: 12px">
            {{ t('patrol.mcp.noStreamList') }}
          </div>
        </div>

        <div class="detail-block">
          <div class="detail-label">{{ t('patrol.mcp.current') }}</div>
          <div class="stream-row">
            <div v-for="c in mcpInfo.configured_streams || []" :key="c.name" class="stream-chip"
                 :class="{ 'stream-bad': c.exists === false }">
              <span class="stream-name">{{ c.name }}</span>
              <span class="mono text-muted">{{ c.stream_id || t('patrol.mcp.unset') }}</span>
              <el-tag v-if="c.exists === false" size="small" type="danger">{{ t('patrol.mcp.missingStream') }}</el-tag>
            </div>
          </div>
        </div>
      </template>
      <template #footer><el-button @click="mcpVisible = false">{{ t('patrol.mcp.close') }}</el-button></template>
    </el-dialog>

    <el-drawer v-model="cfgVisible" :title="t('patrol.cfg.title')" size="800px" :close-on-click-modal="false">
      <el-form v-loading="cfgLoading" :model="form" label-width="140px" label-position="right">
        <el-form-item :label="t('patrol.cfg.enabled')">
          <el-switch v-model="form.enabled" />
          <span class="form-hint" style="margin-left: 10px">{{ t('patrol.cfg.enabledHint') }}</span>
        </el-form-item>

        <el-form-item :label="t('patrol.cfg.url')" required>
          <el-input v-model="form.mcp_url" clearable placeholder="https://graylog.example.com/api/mcp" />
          <div class="form-hint">{{ t('patrol.cfg.urlHint') }}</div>
        </el-form-item>

        <el-form-item :label="t('patrol.cfg.token')">
          <el-input v-model="form.mcp_token" type="password" show-password clearable
                    :placeholder="cfgTokenSet ? t('patrol.cfg.tokenSet', { hint: cfgTokenHint }) : t('patrol.cfg.tokenPlaceholder')" />
          <el-checkbox v-if="cfgTokenSet" v-model="form.clear_token" style="margin-top: 4px">{{ t('patrol.cfg.clearToken') }}</el-checkbox>
          <div class="form-hint">{{ t('patrol.cfg.tokenHint') }}</div>
        </el-form-item>

        <el-form-item :label="t('patrol.cfg.auth')">
          <el-select v-model="form.mcp_auth" style="width: 340px">
            <el-option value="token" :label="t('patrol.cfg.authToken')" />
            <el-option value="bearer" :label="t('patrol.cfg.authBearer')" />
            <el-option value="basic" :label="t('patrol.cfg.authBasic')" />
            <el-option value="raw" :label="t('patrol.cfg.authRaw')" />
            <el-option value="none" :label="t('patrol.cfg.authNone')" />
          </el-select>
        </el-form-item>

        <el-divider content-position="left">{{ t('patrol.cfg.mapping') }}</el-divider>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px">
          <el-button size="small" :loading="streamLoading" @click="fetchStreams">{{ t('patrol.cfg.fetch') }}</el-button>
          <span class="form-hint" style="margin: 0">{{ t('patrol.cfg.fetchHint') }}</span>
        </div>
        <el-table :data="form.streams" size="small" border>
          <el-table-column :label="t('patrol.cfg.role')" width="100">
            <template #default="{ row }"><el-tag size="small" effect="plain">{{ row.name }}</el-tag></template>
          </el-table-column>
          <el-table-column :label="t('patrol.cfg.streamId')" width="340">
            <template #default="{ row }">
              <el-select v-model="row.stream_id" filterable allow-create clearable size="small"
                         :placeholder="t('patrol.cfg.selectStream')" style="width: 100%">
                <el-option v-for="opt in streamOptions" :key="opt.id" :value="opt.id"
                           :label="`${opt.title} (${opt.id})`" />
              </el-select>
              <div v-if="streamTitle(row.stream_id)" class="stream-title">{{ streamTitle(row.stream_id) }}</div>
              <div v-else-if="row.stream_id" class="stream-title warn">{{ t('patrol.cfg.notInList') }}</div>
            </template>
          </el-table-column>
          <el-table-column :label="t('patrol.cfg.query')">
            <template #default="{ row }">
              <el-input v-model="row.query" size="small" :placeholder="t('patrol.cfg.queryPlaceholder')" />
            </template>
          </el-table-column>
        </el-table>

        <el-divider content-position="left">{{ t('patrol.cfg.cadence') }}</el-divider>
        <el-row :gutter="12">
          <el-col :span="12">
            <el-form-item :label="t('patrol.cfg.interval')">
              <el-input-number v-model="form.interval_seconds" :min="60" :max="3600" :step="60" controls-position="right" />
              <span class="unit">{{ t('patrol.cfg.second') }}</span>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item :label="t('patrol.cfg.overlap')">
              <el-input-number v-model="form.overlap_seconds" :min="0" :max="600" :step="10" controls-position="right" />
              <span class="unit">{{ t('patrol.cfg.second') }}</span>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item :label="t('patrol.cfg.repeat')">
              <el-input-number v-model="form.repeat_hours" :min="1" :max="720" controls-position="right" />
              <span class="unit">{{ t('patrol.cfg.hour') }}</span>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item :label="t('patrol.cfg.maxRecords')">
              <el-input-number v-model="form.max_records" :min="100" :max="10000" :step="100" controls-position="right" />
              <span class="unit">{{ t('patrol.cfg.record') }}</span>
            </el-form-item>
          </el-col>
        </el-row>

        <el-collapse style="margin-top: 4px">
          <el-collapse-item :title="t('patrol.cfg.advanced')" name="adv">
            <el-form-item :label="t('patrol.cfg.searchTool')">
              <el-input v-model="form.mcp_tool" placeholder="search_messages" />
            </el-form-item>
            <el-form-item :label="t('patrol.cfg.streamTool')">
              <el-input v-model="form.mcp_stream_tool" placeholder="list_streams" />
            </el-form-item>
            <el-form-item :label="t('patrol.cfg.args')">
              <el-input v-model="form.mcp_args" type="textarea" :rows="2"
                        placeholder='{"query":"${query}","stream_id":"${stream_id}","from":"${from}","to":"${to}","limit":${limit}}' />
              <div class="form-hint">{{ t('patrol.cfg.argsHint') }}</div>
            </el-form-item>
            <el-form-item :label="t('patrol.cfg.timeout')">
              <el-input-number v-model="form.timeout_seconds" :min="5" :max="120" controls-position="right" />
              <span class="unit">{{ t('patrol.cfg.second') }}</span>
            </el-form-item>
          </el-collapse-item>
        </el-collapse>

        <div v-if="cfgSource === 'env'" class="form-hint" style="margin-top: 12px">
          {{ t('patrol.cfg.fromEnv') }}
        </div>
        <div v-else-if="cfgUpdatedBy" class="form-hint" style="margin-top: 12px">
          {{ t('patrol.cfg.lastModified', { by: cfgUpdatedBy }) }}<span v-if="cfgUpdatedAt"> · {{ fmtTime(cfgUpdatedAt) }}</span>
        </div>
      </el-form>

      <template #footer>
        <el-button :loading="cfgProbing" @click="probe">{{ t('patrol.cfg.test') }}</el-button>
        <el-button @click="cfgVisible = false">{{ t('common.action.cancel') }}</el-button>
        <el-button type="primary" :loading="cfgSaving" @click="saveConfig">{{ t('patrol.cfg.save') }}</el-button>
      </template>
    </el-drawer>

    <el-drawer v-model="detailVisible" :title="t('patrol.detail.title')" size="620px">
      <template v-if="detail">
        <div class="detail-head">
          <el-tag size="small" :type="detail.status === 'ok' ? 'success' : 'warning'">{{ statusText(detail.status) }}</el-tag>
          <span class="mono text-muted">#{{ detail.id }}</span>
          <span class="text-muted">{{ fmtTime(detail.created_at) }}</span>
        </div>
        <div class="detail-block">
          <div class="detail-label">{{ t('patrol.detail.window') }}</div>
          <div class="mono">{{ fmtTime(detail.window_start) }} → {{ fmtTime(detail.window_end) }}</div>
        </div>
        <div class="detail-block">
          <div class="detail-label">{{ t('patrol.detail.conclusion') }}</div>
          <div>{{ t('patrol.detail.conclusionText', { fetched: detail.fetched, candidates: detail.candidate_count, would: detail.would_block, blocked: detail.blocked }) }}</div>
          <div v-if="detail.error" class="detail-error">{{ detail.error }}</div>
        </div>
        <div class="detail-block">
          <div class="detail-label">{{ t('patrol.detail.candidates') }}</div>
          <el-table :data="detail.candidates || []" size="small" :empty-text="t('patrol.detail.none')">
            <el-table-column prop="ip_value" :label="t('patrol.col.ip')" width="130">
              <template #default="{ row }"><span class="mono">{{ row.ip_value }}</span></template>
            </el-table-column>
            <el-table-column prop="hits" :label="t('patrol.col.hits')" width="80" align="right" />
            <el-table-column :label="t('patrol.detail.reason')" min-width="160">
              <template #default="{ row }">
                <span style="font-size: 12px">{{ (row.rules || []).map((r) => r.name).join(' / ') || '—' }}</span>
              </template>
            </el-table-column>
            <el-table-column :label="t('patrol.detail.verdict')" width="120">
              <template #default="{ row }">
                <el-tag size="small" :type="decisionType(row.decision)">{{ decisionText(row.decision) }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </div>
        <div class="detail-block">
          <div class="detail-label">{{ t('patrol.detail.summary') }}</div>
          <pre class="detail-json">{{ JSON.stringify(detail.summary, null, 2) }}</pre>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Connection, Setting, VideoPlay, Warning } from '@element-plus/icons-vue'
import { api } from '../api'

const { t, te } = useI18n()
const run = ref(null)
const runs = ref([])
const total = ref(0)
const page = ref(1)
const loading = ref(false)
const running = ref(false)
const mcpLoading = ref(false)
const mcpVisible = ref(false)
const mcpInfo = ref(null)

// ---- Graylog MCP 配置 ----
const cfgVisible = ref(false)
const cfgLoading = ref(false)
const cfgSaving = ref(false)
const cfgProbing = ref(false)
const cfgTokenSet = ref(false)
const cfgTokenHint = ref('')
const cfgSource = ref('env')
const cfgUpdatedBy = ref('')
const cfgUpdatedAt = ref('')
const streamLoading = ref(false)
const streamOptions = ref([])
const form = reactive({
  enabled: false,
  mcp_url: '',
  mcp_token: '',
  clear_token: false,
  mcp_auth: 'token',
  mcp_tool: 'search_messages',
  mcp_stream_tool: 'list_streams',
  mcp_args: '',
  streams: [],
  interval_seconds: 300,
  overlap_seconds: 60,
  repeat_hours: 24,
  max_records: 2000,
  timeout_seconds: 30,
})
const detailVisible = ref(false)
const detail = ref(null)

const summary = computed(() => run.value?.summary || {})
const configuredStreams = computed(
  () => (summary.value.streams || []).filter((s) => !s.skipped).length,
)

// 规则名由后端给出（r.name 已是可读中文），本地只维护「处置预判」枚举
const RULE_TYPE = {
  intel_hit: 'danger', ips_observed: 'warning', waf_observed: 'warning',
  ztna_burst: 'danger', high_freq: 'info', multi_stream: 'info',
}
const DECISION_TYPE = {
  would_block: 'danger', skipped_whitelist: 'info',
  skipped_existing: 'success', skipped_repeat: 'warning',
}

function pick(namespace, value) {
  if (!value) return '-'
  const key = `${namespace}.${value}`
  return te(key) ? t(key) : value
}
function ruleType(key) { return RULE_TYPE[key] || 'info' }
function decisionText(key) { return pick('patrol.decision', key) }
function decisionType(key) { return DECISION_TYPE[key] || 'info' }
function statusText(status) { return pick('patrol.status', status) }
function pad(n) { return String(n).padStart(2, '0') }
function fmtTime(value) {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return String(value)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
function fmtShort(value) {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return String(value)
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

async function loadLatest() {
  loading.value = true
  try {
    run.value = await api.patrolLatest()
  } finally { loading.value = false }
}

async function loadRuns() {
  loading.value = true
  try {
    const data = await api.patrolRuns({ page: page.value, page_size: 10 })
    runs.value = data.items || []
    total.value = data.total || 0
  } finally { loading.value = false }
}

async function doRun() {
  running.value = true
  try {
    run.value = await api.patrolRun()
    ElMessage.success(t('patrol.toast.done', { fetched: run.value.fetched, n: run.value.candidate_count }))
    loadRuns()
  } catch (e) {
    if (e?.response?.status !== 401) ElMessage.error(e?.message || t('patrol.toast.failed'))
  } finally { running.value = false }
}

function streamTitle(id) {
  if (!id) return ''
  return (streamOptions.value.find((s) => s.id === id) || {}).title || ''
}

function mergeStreamOptions(streams) {
  if (!Array.isArray(streams) || !streams.length) return
  const known = new Set(streamOptions.value.map((s) => s.id))
  streamOptions.value = [
    ...streamOptions.value,
    ...streams.filter((s) => s && s.id && !known.has(s.id)),
  ]
}

async function openConfig() {
  cfgVisible.value = true
  cfgLoading.value = true
  try {
    const cfg = await api.patrolConfig()
    Object.assign(form, {
      enabled: cfg.enabled,
      mcp_url: cfg.mcp_url || '',
      mcp_token: '',
      clear_token: false,
      mcp_auth: cfg.mcp_auth || 'token',
      mcp_tool: cfg.mcp_tool || 'search_messages',
      mcp_stream_tool: cfg.mcp_stream_tool || 'list_streams',
      mcp_args: cfg.mcp_args || '',
      streams: (cfg.streams || []).map((s) => ({ ...s })),
      interval_seconds: cfg.interval_seconds || 300,
      overlap_seconds: cfg.overlap_seconds ?? 60,
      repeat_hours: cfg.repeat_hours || 24,
      max_records: cfg.max_records || 2000,
      timeout_seconds: Math.round(cfg.timeout_seconds || 30),
    })
    cfgTokenSet.value = !!cfg.token_set
    cfgTokenHint.value = cfg.token_hint || ''
    cfgSource.value = cfg.source || 'env'
    cfgUpdatedBy.value = cfg.updated_by || ''
    cfgUpdatedAt.value = cfg.updated_at || ''
  } catch (e) { /* 拦截器已提示 */ } finally { cfgLoading.value = false }
}

function draftPayload() {
  const payload = {
    enabled: form.enabled,
    mcp_url: form.mcp_url,
    mcp_auth: form.mcp_auth,
    mcp_tool: form.mcp_tool,
    mcp_stream_tool: form.mcp_stream_tool,
    mcp_args: form.mcp_args,
    streams: form.streams,
    interval_seconds: form.interval_seconds,
    overlap_seconds: form.overlap_seconds,
    repeat_hours: form.repeat_hours,
    max_records: form.max_records,
    timeout_seconds: form.timeout_seconds,
  }
  if (form.mcp_token) payload.mcp_token = form.mcp_token
  if (form.clear_token) payload.clear_token = true
  return payload
}

async function fetchStreams() {
  if (!form.mcp_url) { ElMessage.warning(t('patrol.toast.needUrl')); return }
  streamLoading.value = true
  try {
    const info = await api.patrolMcpTest({
      mcp_url: form.mcp_url,
      mcp_auth: form.mcp_auth,
      mcp_token: form.mcp_token || undefined,
      mcp_tool: form.mcp_tool,
      mcp_stream_tool: form.mcp_stream_tool,
      streams: form.streams,
    })
    if (info.error) { ElMessage.error(t('patrol.toast.streamFail', { err: info.error })); return }
    mergeStreamOptions(info.streams)
    ElMessage.success(t('patrol.toast.fetched', { n: info.streams?.length || 0 }))
  } catch (e) { /* 拦截器已提示 */ } finally { streamLoading.value = false }
}

async function probe() {
  cfgProbing.value = true
  try {
    const info = await api.patrolMcpTest(draftPayload())
    if (info.error) { ElMessage.error(t('patrol.toast.mcpDown', { err: info.error })); return }
    mergeStreamOptions(info.streams)
    const tools = (info.tools || []).map((tool) => tool.name).join(', ') || t('patrol.toast.noTools')
    ElMessage.success(t('patrol.toast.connOk', {
      server: info.server?.name || 'unknown',
      transport: info.transport,
      tools,
    }))
  } catch (e) { /* 拦截器已提示 */ } finally { cfgProbing.value = false }
}

async function saveConfig() {
  if (!form.mcp_url) { ElMessage.warning(t('patrol.toast.needUrl')); return }
  cfgSaving.value = true
  try {
    await api.patrolConfigSave(draftPayload())
    ElMessage.success(t('patrol.toast.saved'))
    cfgVisible.value = false
    await Promise.all([loadLatest(), loadRuns()])
  } catch (e) { /* 拦截器已提示 */ } finally { cfgSaving.value = false }
}

async function testMcp() {
  mcpLoading.value = true
  try {
    const info = await api.patrolMcpStatus()
    if (!info.configured) {
      ElMessage.warning(info.error || t('patrol.toast.notConfigured'))
      return
    }
    if (info.error) {
      ElMessage.error(t('patrol.toast.mcpDown', { err: info.error }))
      return
    }
    mcpInfo.value = info
    mcpVisible.value = true
  } finally { mcpLoading.value = false }
}

async function copyStream(id) {
  try {
    await navigator.clipboard.writeText(id)
    ElMessage.success(t('patrol.toast.copied', { id }))
  } catch (e) {
    ElMessage.warning(t('patrol.toast.copyDenied'))
  }
}

async function openDetail(row) {
  detail.value = await api.patrolRunDetail(row.id)
  detailVisible.value = true
}

onMounted(async () => {
  await Promise.all([loadLatest(), loadRuns()])
})
</script>

<style scoped>
.stream-row { display: flex; flex-wrap: wrap; gap: 8px; }
.stream-chip { display: flex; align-items: center; gap: 8px; font-size: 12px; background: var(--el-fill-color-light); border-radius: 6px; padding: 5px 10px; }
.stream-chip.stream-bad { background: var(--el-color-danger-light-9); }
.stream-name { font-weight: 600; }
.form-hint { font-size: 12px; color: var(--el-text-color-secondary); line-height: 1.6; }
.stream-title { font-size: 12px; color: var(--el-text-color-secondary); margin-top: 2px; }
.stream-title.warn { color: var(--el-color-warning); }
.unit { margin-left: 6px; font-size: 12px; color: var(--el-text-color-secondary); }
.clickable { cursor: pointer; }
.clickable:hover { color: var(--el-color-primary); }
</style>
