<template>
  <div>
    <div class="page-header">
      <div>
        <h2 class="page-title">AI 巡检</h2>
        <p class="page-desc">
          先看防护有没有生效（三流覆盖 / 封禁缺口 / 处置率 / 持续攻击），再看平台是否健康（设备、任务、策略、白名单）；
          输出加权健康分与可执行建议，每天 08:30 自动巡检一次
        </p>
      </div>
      <el-button type="primary" :loading="running" @click="run">立即巡检</el-button>
    </div>

    <div v-if="report" class="table-card">
      <div class="report-top">
        <div class="score-box">
          <el-progress type="dashboard" :percentage="report.score"
                       :color="scoreColor" :stroke-width="14" :width="140">
            <template #default>
              <div class="score-num">{{ report.score }}</div>
              <div class="score-label">健康分</div>
            </template>
          </el-progress>
        </div>
        <div class="report-meta">
          <div class="meta-line">
            <el-tag :type="OVERALL_TAG[report.overall]" effect="dark" size="small">{{ OVERALL_LABEL[report.overall] }}</el-tag>
            <el-tag v-if="report.ai_enhanced" type="warning" size="small" effect="plain">AI 生成总结</el-tag>
            <el-tag v-else size="small" type="info" effect="plain">规则总结（配置 AI_LLM_* 后自动启用大模型）</el-tag>
            <span class="text-muted">耗时 {{ report.duration_ms }} ms · {{ fmt(report.created_at) }} · 触发方式 {{ report.trigger === 'cron' ? '定时' : '手动' }}</span>
          </div>
          <div class="summary">{{ report.summary }}</div>
        </div>
      </div>

      <div class="kpi-strip">
        <div class="kpi">
          <div class="kpi-label">24h 处置率</div>
          <div class="kpi-value" :style="{ color: rateColor(m.detection_rate_24h) }">{{ pct(m.detection_rate_24h) }}</div>
          <div class="kpi-sub">近 7 日 {{ pct(m.detection_rate_7d) }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">可处置缺口</div>
          <div class="kpi-value" :style="{ color: m.gap_ips_24h ? 'var(--el-color-warning)' : 'var(--el-color-success)' }">
            {{ m.gap_ips_24h ?? '—' }}<span class="unit">个 IP</span>
          </div>
          <div class="kpi-sub">检出 {{ m.detected_ips_24h ?? 0 }} · 封禁 {{ m.blocked_ips_24h ?? 0 }} · 豁免 {{ m.exempt_ips_24h ?? 0 }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">24h 封禁次数</div>
          <div class="kpi-value">{{ m.blocked_24h ?? 0 }}</div>
          <div class="kpi-sub">峰值 {{ m.peak_hour || '—' }}<span v-if="m.peak_hour">（{{ m.peak_count }} 次）</span></div>
        </div>
        <div class="kpi">
          <div class="kpi-label">跨日持续攻击</div>
          <div class="kpi-value" :style="{ color: m.persistent_ips ? 'var(--el-color-warning)' : 'var(--el-color-success)' }">
            {{ m.persistent_ips ?? 0 }}<span class="unit">个 IP</span>
          </div>
          <div class="kpi-sub">近 7 天跨 ≥3 天出现</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">数据源覆盖</div>
          <div class="kpi-value" :style="{ color: (m.missing_sources || []).length ? 'var(--el-color-warning)' : 'var(--el-color-success)' }">
            {{ m.core_sources ?? m.active_sources ?? 0 }}<span class="unit">/ 3 路</span>
          </div>
          <div class="kpi-sub">{{ (m.missing_sources || []).length ? '缺 ' + m.missing_sources.join(' / ') : 'IPS / WAF / 零信任齐全' }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">较上次巡检</div>
          <div class="kpi-value" :style="{ color: deltaColor }">{{ deltaText }}</div>
          <div class="kpi-sub">{{ m.previous_score != null ? '上次 ' + m.previous_score + ' 分' : '首次巡检，无对比' }}</div>
        </div>
      </div>
    </div>
    <el-empty v-else-if="!loading" description="还没有巡检报告，点右上角「立即巡检」做第一次体检" style="margin-top: 60px" />

    <div v-if="report" class="check-grid">
      <div v-for="c in report.checks" :key="c.key" class="check-card" :class="'check-' + c.status">
        <div class="check-head">
          <span class="check-icon">{{ STATUS_ICON[c.status] }}</span>
          <span class="check-name">{{ c.name }}</span>
          <el-tag size="small" :type="STATUS_TAG[c.status]" effect="plain">{{ STATUS_LABEL[c.status] }}</el-tag>
        </div>
        <div class="check-summary">{{ c.summary }}</div>
        <div v-if="c.advice" class="check-advice">💡 {{ c.advice }}</div>

        <!-- 封禁缺口：原因归因 + 高频缺口 IP -->
        <div v-if="c.key === 'gap' && (c.data.reasons || []).length" class="check-detail">
          <div v-for="r in c.data.reasons" :key="r.key" class="detail-row">
            <span class="dot" :class="r.exempt ? 'dot-gray' : 'dot-warn'"></span>
            <span class="detail-name">{{ r.label }}</span>
            <span class="detail-num">{{ r.ip_count }} IP / {{ r.alert_count }} 条</span>
            <el-tag v-if="r.exempt" size="small" type="info" effect="plain">设计内豁免</el-tag>
          </div>
          <div v-if="(c.data.top_gaps || []).length" class="sample-list">
            <div v-for="g in c.data.top_gaps.slice(0, 3)" :key="g.ip" class="mono">
              {{ g.ip }}<span v-if="g.country" class="text-muted"> · {{ g.country }}</span>
              ×{{ g.count }} · {{ g.label }}
            </div>
          </div>
        </div>

        <!-- 三流覆盖 -->
        <div v-if="c.key === 'sources' && (c.data.items || []).length" class="src-chips">
          <span v-for="s in c.data.items" :key="s.source" class="src-chip">
            <b>{{ s.source }}</b> {{ s.alerts }} 条<span class="text-muted"> / 封 {{ s.blocked }}</span>
          </span>
        </div>

        <!-- 处置率 7 日趋势 -->
        <div v-if="c.key === 'detection' && (c.data.series || []).length" class="spark">
          <div v-for="d in c.data.series" :key="d.date" class="spark-col"
               :title="`${d.date} 处置率 ${pct(d.rate)}（封 ${d.blocked} / 检 ${d.detected}，豁免 ${d.exempt}）`">
            <div class="spark-bar" :style="{ height: barHeight(d.rate), background: rateColor(d.rate) }"></div>
            <span class="spark-date">{{ d.date.slice(5) }}</span>
          </div>
        </div>

        <!-- 跨日持续攻击源 -->
        <div v-if="c.key === 'persistent' && (c.data.items || []).length" class="check-detail">
          <div v-for="p in c.data.items" :key="p.ip" class="mono">
            {{ p.ip }}<span v-if="p.country" class="text-muted"> · {{ p.country }}</span>
            · {{ p.days }} 天 / {{ p.hits }} 次 → 建议封 {{ p.suggest_hours }}h
          </div>
        </div>

        <div v-if="c.key === 'attacks' && c.data && (c.data.repeat_offenders || []).length" class="check-detail">
          <div v-for="r in c.data.repeat_offenders" :key="r.ip" class="mono">⚠ {{ r.ip }} 7 天命中 {{ r.count }} 次</div>
        </div>
        <div v-if="c.key === 'devices' && c.data && (c.data.offline || []).length" class="check-detail">
          <div v-for="d in c.data.offline" :key="d.device" class="mono">✗ {{ d.device }}（{{ d.plugin }}）：{{ d.message }}</div>
        </div>
      </div>
    </div>

    <div class="table-card" style="margin-top: 16px">
      <div class="card-title">历史报告</div>
      <el-table :data="history" size="small" stripe @row-click="showReport">
        <el-table-column prop="created_at" label="巡检时间" width="170">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="score" label="健康分" width="120">
          <template #default="{ row }">
            <span :style="{ color: row.score >= 80 ? 'var(--el-color-success)' : row.score >= 55 ? 'var(--el-color-warning)' : 'var(--el-color-danger)', fontWeight: 600 }">{{ row.score }}</span>
            <span v-if="row.metrics && row.metrics.score_delta != null" class="delta"
                  :style="{ color: deltaColorOf(row.metrics.score_delta) }">
              {{ signed(row.metrics.score_delta) }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="处置率" width="110">
          <template #default="{ row }">
            <span v-if="row.metrics && row.metrics.detection_rate_24h != null"
                  :style="{ color: rateColor(row.metrics.detection_rate_24h) }">
              {{ pct(row.metrics.detection_rate_24h) }}
            </span>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>
        <el-table-column label="缺口" width="90">
          <template #default="{ row }">
            <span v-if="row.metrics">{{ row.metrics.gap_ips_24h ?? '—' }}</span>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>
        <el-table-column prop="overall" label="总体" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="OVERALL_TAG[row.overall]">{{ OVERALL_LABEL[row.overall] }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="trigger" label="触发" width="80">
          <template #default="{ row }">{{ row.trigger === 'cron' ? '定时' : '手动' }}</template>
        </el-table-column>
        <el-table-column prop="summary" label="总结" min-width="280" show-overflow-tooltip />
        <el-table-column prop="created_by" label="执行人" width="100" />
      </el-table>
      <div class="pager">
        <el-pagination background layout="total, prev, pager, next" :total="total"
                       :page-size="query.page_size" :current-page="query.page"
                       @current-change="(p) => { query.page = p; loadHistory() }" />
      </div>
    </div>

    <el-dialog v-model="detailVisible" title="巡检报告详情" width="820px">
      <template v-if="detail">
        <div class="detail-head">
          <el-tag :type="OVERALL_TAG[detail.overall]" effect="dark">{{ OVERALL_LABEL[detail.overall] }} · {{ detail.score }} 分</el-tag>
          <span class="text-muted">{{ fmt(detail.created_at) }} · {{ detail.duration_ms }} ms</span>
          <span v-if="detail.metrics && detail.metrics.detection_rate_24h != null" class="text-muted">
            · 处置率 {{ pct(detail.metrics.detection_rate_24h) }} · 缺口 {{ detail.metrics.gap_ips_24h }} 个 IP
          </span>
        </div>
        <div class="summary" style="margin: 12px 0">{{ detail.summary }}</div>
        <el-collapse>
          <el-collapse-item v-for="c in detail.checks" :key="c.key" :name="c.key">
            <template #title>
              <span style="margin-right: 8px">{{ STATUS_ICON[c.status] }}</span>
              <b>{{ c.name }}</b>
              <el-tag size="small" :type="STATUS_TAG[c.status]" effect="plain" style="margin-left: 8px">{{ STATUS_LABEL[c.status] }}</el-tag>
              <span class="text-muted" style="margin-left: 12px">{{ c.summary }}</span>
            </template>
            <div v-if="c.advice" class="check-advice">💡 {{ c.advice }}</div>
            <pre class="detail-json">{{ JSON.stringify(c.data, null, 2) }}</pre>
          </el-collapse-item>
        </el-collapse>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const report = ref(null)
const history = ref([])
const total = ref(0)
const loading = ref(false)
const running = ref(false)
const detail = ref(null)
const detailVisible = ref(false)
const query = reactive({ page: 1, page_size: 10 })

const OVERALL_TAG = { ok: 'success', warn: 'warning', fail: 'danger' }
const OVERALL_LABEL = { ok: '健康', warn: '需关注', fail: '有问题' }
const STATUS_ICON = { ok: '✅', warn: '⚠️', fail: '❌' }
const STATUS_TAG = { ok: 'success', warn: 'warning', fail: 'danger' }
const STATUS_LABEL = { ok: '正常', warn: '警告', fail: '异常' }
const scoreColor = (p) => (p >= 80 ? '#67c23a' : p >= 55 ? '#e6a23c' : '#f56c6c')

const m = computed(() => (report.value && report.value.metrics) || {})

function pct(value) {
  if (value === null || value === undefined) return '—'
  return `${Math.round(value * 100)}%`
}

function rateColor(value) {
  if (value === null || value === undefined) return 'var(--el-text-color-secondary)'
  if (value >= 0.85) return 'var(--el-color-success)'
  if (value >= 0.6) return 'var(--el-color-warning)'
  return 'var(--el-color-danger)'
}

function barHeight(value) {
  if (value === null || value === undefined) return '4px'
  return `${Math.max(8, Math.round(value * 46))}px`
}

function deltaColorOf(delta) {
  if (delta === null || delta === undefined) return 'var(--el-text-color-secondary)'
  if (delta > 0) return 'var(--el-color-success)'
  if (delta < 0) return 'var(--el-color-danger)'
  return 'var(--el-text-color-secondary)'
}

const deltaColor = computed(() => deltaColorOf(m.value.score_delta))

const deltaText = computed(() => {
  const delta = m.value.score_delta
  if (delta === null || delta === undefined) return '—'
  return signed(delta)
})

function signed(value) {
  if (value === null || value === undefined) return '—'
  return value > 0 ? `+${value}` : `${value}`
}

function fmt(value) {
  if (!value) return ''
  return String(value).replace('T', ' ').slice(0, 19)
}

async function loadLatest() {
  loading.value = true
  try {
    report.value = await api.inspectionLatest()
  } catch (e) { /* 拦截器已提示 */ } finally { loading.value = false }
}

async function loadHistory() {
  try {
    const data = await api.inspectionReports({ page: query.page, page_size: query.page_size })
    history.value = data.items
    total.value = data.total
  } catch (e) { /* 拦截器已提示 */ }
}

async function run() {
  running.value = true
  try {
    report.value = await api.inspectionRun()
    ElMessage.success(`巡检完成：健康分 ${report.value.score}（${OVERALL_LABEL[report.value.overall]}）`)
    query.page = 1
    loadHistory()
  } catch (e) { /* 拦截器已提示 */ } finally { running.value = false }
}

async function showReport(row) {
  try {
    detail.value = await api.inspectionReport(row.id)
    detailVisible.value = true
  } catch (e) { /* 拦截器已提示 */ }
}

onMounted(() => { loadLatest(); loadHistory() })
</script>

<style scoped>
.report-top { display: flex; gap: 28px; align-items: center; }
.score-box { flex-shrink: 0; }
.score-num { font-size: 34px; font-weight: 700; line-height: 1.1; }
.score-label { font-size: 12px; color: var(--el-text-color-secondary); }
.report-meta { flex: 1; min-width: 0; }
.meta-line { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.summary { margin-top: 12px; line-height: 1.8; font-size: 14px; white-space: pre-wrap; }

.kpi-strip { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-top: 18px; }
.kpi { background: var(--el-fill-color-lighter); border-radius: 8px; padding: 12px 14px; }
.kpi-label { font-size: 12px; color: var(--el-text-color-secondary); }
.kpi-value { font-size: 22px; font-weight: 700; line-height: 1.4; margin-top: 2px; }
.kpi-value .unit { font-size: 12px; font-weight: 400; color: var(--el-text-color-secondary); margin-left: 4px; }
.kpi-sub { font-size: 11px; color: var(--el-text-color-secondary); margin-top: 2px; line-height: 1.5; }

.check-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 14px; margin-top: 16px; }
.check-card { background: var(--el-bg-color); border: 1px solid var(--el-border-color-lighter); border-radius: 8px; padding: 14px 16px; border-left-width: 4px; }
.check-ok { border-left-color: var(--el-color-success); }
.check-warn { border-left-color: var(--el-color-warning); }
.check-fail { border-left-color: var(--el-color-danger); }
.check-head { display: flex; align-items: center; gap: 8px; }
.check-name { font-weight: 600; flex: 1; }
.check-summary { margin-top: 8px; font-size: 13px; line-height: 1.7; color: var(--el-text-color-regular); }
.check-advice { margin-top: 8px; font-size: 12px; color: var(--el-text-color-secondary); background: var(--el-fill-color-light); border-radius: 6px; padding: 6px 10px; }
.check-detail { margin-top: 8px; font-size: 12px; color: var(--el-text-color-regular); }

.detail-row { display: flex; align-items: center; gap: 6px; padding: 2px 0; }
.dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.dot-warn { background: var(--el-color-warning); }
.dot-gray { background: var(--el-color-info-light-5); }
.detail-name { flex: 0 0 auto; }
.detail-num { flex: 1; text-align: right; color: var(--el-text-color-secondary); }
.sample-list { margin-top: 6px; padding-top: 6px; border-top: 1px dashed var(--el-border-color-lighter); }

.src-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.src-chip { font-size: 12px; background: var(--el-fill-color-light); border-radius: 4px; padding: 3px 8px; }

.spark { display: flex; align-items: flex-end; gap: 6px; margin-top: 10px; height: 74px; }
.spark-col { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; gap: 3px; }
.spark-bar { width: 100%; max-width: 26px; border-radius: 3px 3px 0 0; opacity: .85; }
.spark-date { font-size: 10px; color: var(--el-text-color-secondary); }

.card-title { font-weight: 600; margin-bottom: 10px; }
.delta { font-size: 11px; margin-left: 4px; }
.detail-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.detail-json { font-size: 12px; background: var(--el-fill-color-light); border-radius: 6px; padding: 10px; max-height: 240px; overflow: auto; }
</style>
