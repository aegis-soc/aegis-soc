<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h2 class="page-title">日志巡检</h2>
        <p class="page-desc">
          通过 MCP 只读查询 Graylog 三流日志（IPS / WAF / 零信任），用确定性规则找出 Graylog 规则漏掉的攻击源。
          当前为 <b>dry-run</b>：只出报告，不创建黑名单、不下发封禁。
        </p>
      </div>
      <div style="display: flex; gap: 8px">
        <el-button :icon="Connection" :loading="mcpLoading" @click="testMcp">MCP 连通性</el-button>
        <el-button type="primary" :icon="VideoPlay" :loading="running" @click="doRun">立即巡检</el-button>
      </div>
    </div>

    <el-alert
      v-if="!run" type="info" show-icon :closable="false"
      title="还没有巡检记录"
      description="配置 PATROL_MCP_URL 与 PATROL_STREAMS 后，点「立即巡检」跑第一轮；定时任务默认每 5 分钟一次（需 PATROL_ENABLED=true）。"
      style="margin-bottom: 16px"
    />
    <el-alert
      v-else-if="run.status !== 'ok'" :type="run.status === 'skipped' ? 'warning' : 'error'"
      show-icon :closable="false" :title="statusText(run.status)"
      :description="run.error || '部分日志流读取失败，本轮结论仅供参考'" style="margin-bottom: 16px"
    />

    <template v-if="run">
      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-label">巡检窗口</div>
          <div class="stat-value" style="font-size: 15px">{{ fmtShort(run.window_start) }} → {{ fmtShort(run.window_end) }}</div>
          <div class="stat-hint">与上一轮重叠 {{ summary.window?.overlap_seconds ?? 0 }}s，避免窗口缝隙漏日志</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">📥 拉取日志</div>
          <div class="stat-value">{{ run.fetched }}</div>
          <div class="stat-hint">{{ configuredStreams }} 条流 · 耗时 {{ run.duration_ms }} ms</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">🎯 候选 IP</div>
          <div class="stat-value">{{ run.candidate_count }}</div>
          <div class="stat-hint">忽略非公网地址 {{ summary.ignored_non_public ?? 0 }} 条</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">⚠️ 过闸门可封</div>
          <div class="stat-value" :style="{ color: run.would_block ? 'var(--el-color-danger)' : undefined }">{{ run.would_block }}</div>
          <div class="stat-hint">白名单 / 已封 / 重复命中已被排除</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">🔒 实际封禁</div>
          <div class="stat-value">0</div>
          <div class="stat-hint">P0 只读：不建 IOC、不下发任务</div>
        </div>
      </div>

      <div class="table-card" style="margin-bottom: 16px">
        <div class="card-title">日志流状态</div>
        <div class="stream-row">
          <div v-for="s in summary.streams || []" :key="s.name" class="stream-chip" :class="{ 'stream-bad': s.error }">
            <span class="stream-name">{{ s.name }}</span>
            <span class="stream-meta">{{ s.error ? '读取失败' : s.skipped ? s.skipped : `${s.fetched} 条` }}</span>
            <el-tooltip v-if="s.error" :content="s.error" placement="top">
              <el-icon class="stream-err"><Warning /></el-icon>
            </el-tooltip>
          </div>
          <span v-if="!(summary.streams || []).length" class="text-muted">未配置日志流</span>
        </div>
        <div v-if="(summary.rules || []).length" class="rule-row">
          <span class="text-muted" style="font-size: 12px">命中规则：</span>
          <el-tag v-for="r in summary.rules" :key="r.key" size="small" :type="ruleType(r.key)" effect="plain">
            {{ r.name }} × {{ r.count }}
          </el-tag>
        </div>
      </div>

      <div class="table-card">
        <div class="card-title">候选 IP（本轮）</div>
        <el-table :data="run.candidates" v-loading="loading" size="small" empty-text="本轮没有命中任何规则">
          <el-table-column prop="ip_value" label="IP" width="150">
            <template #default="{ row }"><span class="mono">{{ row.ip_value }}</span></template>
          </el-table-column>
          <el-table-column prop="streams" label="命中流" width="110">
            <template #default="{ row }">
              <el-tag v-for="s in (row.streams || '').split(',').filter(Boolean)" :key="s" size="small" style="margin-right: 4px">{{ s }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="hits" label="条数" width="70" align="right" />
          <el-table-column label="严重度" width="90">
            <template #default="{ row }">
              <el-rate :model-value="row.severity" disabled :max="5" size="small" />
            </template>
          </el-table-column>
          <el-table-column label="命中原因" min-width="240">
            <template #default="{ row }">
              <el-tag v-for="r in row.rules || []" :key="r.key" size="small" :type="ruleType(r.key)" style="margin: 2px 4px 2px 0">
                {{ r.name }}<span v-if="r.count > 1"> ×{{ r.count }}</span>
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="处置预判" width="150">
            <template #default="{ row }">
              <el-tooltip :content="row.decision_reason || ''" placement="top">
                <el-tag size="small" :type="decisionType(row.decision)">{{ decisionText(row.decision) }}</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="最近命中" width="160">
            <template #default="{ row }"><span class="mono text-muted">{{ fmtTime(row.last_seen) }}</span></template>
          </el-table-column>
        </el-table>
      </div>
    </template>

    <div class="table-card" style="margin-top: 16px">
      <div class="card-title">历史批次</div>
      <el-table :data="runs" v-loading="loading" size="small" empty-text="暂无记录">
        <el-table-column label="时间" width="170">
          <template #default="{ row }"><span class="mono">{{ fmtTime(row.created_at) }}</span></template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="row.status === 'ok' ? 'success' : row.status === 'skipped' ? 'info' : row.status === 'degraded' ? 'warning' : 'danger'">
              {{ statusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="窗口" min-width="180">
          <template #default="{ row }"><span class="mono text-muted">{{ fmtShort(row.window_start) }} → {{ fmtShort(row.window_end) }}</span></template>
        </el-table-column>
        <el-table-column prop="fetched" label="日志" width="80" align="right" />
        <el-table-column prop="candidate_count" label="候选" width="80" align="right" />
        <el-table-column prop="would_block" label="可封" width="80" align="right" />
        <el-table-column prop="duration_ms" label="耗时(ms)" width="100" align="right" />
        <el-table-column label="操作" width="90">
          <template #default="{ row }">
            <el-button link type="primary" @click="openDetail(row)">查看</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="pager">
        <el-pagination layout="total, prev, pager, next" :total="total" :page-size="10"
                       :current-page="page" @current-change="(p) => { page = p; loadRuns() }" />
      </div>
    </div>

    <el-dialog v-model="mcpVisible" title="MCP 连通性" width="720px">
      <template v-if="mcpInfo">
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="服务端">{{ mcpInfo.server?.name || '—' }} <span class="text-muted">{{ mcpInfo.server?.version || '' }}</span></el-descriptions-item>
          <el-descriptions-item label="协议">{{ mcpInfo.protocol_version || '—' }}</el-descriptions-item>
          <el-descriptions-item label="传输">
            <el-tag size="small" :type="mcpInfo.transport === 'sse' ? 'warning' : 'success'">{{ mcpInfo.transport || '—' }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="鉴权">
            <el-tag size="small" type="info">{{ mcpInfo.auth || '—' }}</el-tag>
            <span class="mono text-muted" style="margin-left: 6px">{{ mcpInfo.token_hint || '无 token' }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="地址" :span="2"><span class="mono">{{ mcpInfo.url }}</span></el-descriptions-item>
        </el-descriptions>

        <div class="detail-block">
          <div class="detail-label">可用工具（{{ (mcpInfo.tools || []).length }}）</div>
          <div class="stream-row">
            <el-tag v-for="t in mcpInfo.tools" :key="t.name" size="small" effect="plain">{{ t.name }}</el-tag>
          </div>
        </div>

        <div class="detail-block">
          <div class="detail-label">Graylog 流清单（点 stream id 复制，填进 PATROL_STREAMS）</div>
          <el-table :data="mcpInfo.streams || []" size="small" max-height="240">
            <el-table-column label="Stream ID" width="290">
              <template #default="{ row }">
                <span class="mono clickable" :title="'点击复制'" @click="copyStream(row.id)">{{ row.id }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="title" label="标题" />
            <el-table-column label="建议角色" width="110">
              <template #default="{ row }">
                <el-tag v-if="row.suggested" size="small" type="success">{{ row.suggested }}</el-tag>
                <span v-else class="text-muted">—</span>
              </template>
            </el-table-column>
          </el-table>
          <div v-if="(mcpInfo.streams || []).length === 0" class="text-muted" style="font-size: 12px">
            未读到流清单（服务端可能没有 list_streams 工具，或该 token 无权限）
          </div>
        </div>

        <div class="detail-block">
          <div class="detail-label">当前配置</div>
          <div class="stream-row">
            <div v-for="c in mcpInfo.configured_streams || []" :key="c.name" class="stream-chip"
                 :class="{ 'stream-bad': c.exists === false }">
              <span class="stream-name">{{ c.name }}</span>
              <span class="mono text-muted">{{ c.stream_id || '未配置' }}</span>
              <el-tag v-if="c.exists === false" size="small" type="danger">流不存在</el-tag>
            </div>
          </div>
        </div>
      </template>
      <template #footer><el-button @click="mcpVisible = false">关闭</el-button></template>
    </el-dialog>

    <el-drawer v-model="detailVisible" title="批次详情" size="620px">
      <template v-if="detail">
        <div class="detail-head">
          <el-tag size="small" :type="detail.status === 'ok' ? 'success' : 'warning'">{{ statusText(detail.status) }}</el-tag>
          <span class="mono text-muted">#{{ detail.id }}</span>
          <span class="text-muted">{{ fmtTime(detail.created_at) }}</span>
        </div>
        <div class="detail-block">
          <div class="detail-label">窗口</div>
          <div class="mono">{{ fmtTime(detail.window_start) }} → {{ fmtTime(detail.window_end) }}</div>
        </div>
        <div class="detail-block">
          <div class="detail-label">结论</div>
          <div>拉取 {{ detail.fetched }} 条日志，识别 {{ detail.candidate_count }} 个候选 IP，其中 {{ detail.would_block }} 个通过闸门（实际封禁 {{ detail.blocked }}）。</div>
          <div v-if="detail.error" class="detail-error">{{ detail.error }}</div>
        </div>
        <div class="detail-block">
          <div class="detail-label">候选明细</div>
          <el-table :data="detail.candidates || []" size="small" empty-text="无">
            <el-table-column prop="ip_value" label="IP" width="130">
              <template #default="{ row }"><span class="mono">{{ row.ip_value }}</span></template>
            </el-table-column>
            <el-table-column prop="hits" label="条数" width="70" align="right" />
            <el-table-column label="原因" min-width="160">
              <template #default="{ row }">
                <span style="font-size: 12px">{{ (row.rules || []).map((r) => r.name).join(' / ') || '—' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="判定" width="110">
              <template #default="{ row }">
                <el-tag size="small" :type="decisionType(row.decision)">{{ decisionText(row.decision) }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </div>
        <div class="detail-block">
          <div class="detail-label">结构化摘要</div>
          <pre class="detail-json">{{ JSON.stringify(detail.summary, null, 2) }}</pre>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Connection, VideoPlay, Warning } from '@element-plus/icons-vue'
import { api } from '../api'

const run = ref(null)
const runs = ref([])
const total = ref(0)
const page = ref(1)
const loading = ref(false)
const running = ref(false)
const mcpLoading = ref(false)
const mcpVisible = ref(false)
const mcpInfo = ref(null)
const detailVisible = ref(false)
const detail = ref(null)

const summary = computed(() => run.value?.summary || {})
const configuredStreams = computed(
  () => (summary.value.streams || []).filter((s) => !s.skipped).length,
)

const RULE_TEXT = {
  intel_hit: '情报命中',
  ips_observed: 'IPS 未阻断',
  waf_observed: 'WAF 放行',
  ztna_burst: '认证爆破',
  high_freq: '高频访问',
  multi_stream: '跨流命中',
}
const RULE_TYPE = {
  intel_hit: 'danger', ips_observed: 'warning', waf_observed: 'warning',
  ztna_burst: 'danger', high_freq: 'info', multi_stream: 'info',
}
const DECISION_TEXT = {
  would_block: '可封禁',
  skipped_whitelist: '白名单豁免',
  skipped_existing: '已在黑名单',
  skipped_repeat: '24h 内已标记',
}
const DECISION_TYPE = {
  would_block: 'danger', skipped_whitelist: 'info',
  skipped_existing: 'success', skipped_repeat: 'warning',
}

function ruleType(key) { return RULE_TYPE[key] || 'info' }
function decisionText(key) { return DECISION_TEXT[key] || key }
function decisionType(key) { return DECISION_TYPE[key] || 'info' }
function statusText(status) {
  return { ok: '正常', degraded: '部分降级', failed: '读取失败', skipped: '已跳过' }[status] || status
}
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
    ElMessage.success(`巡检完成：${run.value.fetched} 条日志，${run.value.candidate_count} 个候选`)
    loadRuns()
  } catch (e) {
    if (e?.response?.status !== 401) ElMessage.error(e?.message || '巡检失败')
  } finally { running.value = false }
}

async function testMcp() {
  mcpLoading.value = true
  try {
    const info = await api.patrolMcpStatus()
    if (!info.configured) {
      ElMessage.warning(info.error || '未配置 PATROL_MCP_URL')
      return
    }
    if (info.error) {
      ElMessage.error(`MCP 不可用：${info.error}`)
      return
    }
    mcpInfo.value = info
    mcpVisible.value = true
  } finally { mcpLoading.value = false }
}

async function copyStream(id) {
  try {
    await navigator.clipboard.writeText(id)
    ElMessage.success(`已复制 ${id}`)
  } catch (e) {
    ElMessage.warning('浏览器拒绝了剪贴板访问，请手动复制')
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
.clickable { cursor: pointer; }
.clickable:hover { color: var(--el-color-primary); }
.stream-meta { color: var(--el-text-color-secondary); }
.stream-err { color: var(--el-color-danger); }
.rule-row { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-top: 12px; }
.detail-head { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
.detail-block { margin-bottom: 18px; }
.detail-label { font-size: 12px; color: var(--el-text-color-secondary); margin-bottom: 6px; }
.detail-error { margin-top: 6px; font-size: 12px; color: var(--el-color-danger); word-break: break-all; }
.detail-json { font-size: 12px; background: var(--el-fill-color-light); border-radius: 6px; padding: 10px; max-height: 260px; overflow: auto; }
</style>
