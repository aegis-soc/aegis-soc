<template>
  <div>
    <div class="page-header">
      <div>
        <h2 class="page-title">{{ t('inspection.title') }}</h2>
        <p class="page-desc">{{ t('inspection.desc') }}</p>
      </div>
      <el-button type="primary" :loading="running" @click="run">{{ t('inspection.run') }}</el-button>
    </div>

    <div v-if="report" class="table-card">
      <div class="report-top">
        <div class="score-box">
          <el-progress type="dashboard" :percentage="report.score"
                       :color="scoreColor" :stroke-width="14" :width="140">
            <template #default>
              <div class="score-num">{{ report.score }}</div>
              <div class="score-label">{{ t('inspection.scoreLabel') }}</div>
            </template>
          </el-progress>
        </div>
        <div class="report-meta">
          <div class="meta-line">
            <el-tag :type="overallTag(report.overall)" effect="dark" size="small">{{ overallLabel(report.overall) }}</el-tag>
            <el-tag v-if="report.ai_enhanced" type="warning" size="small" effect="plain">{{ t('inspection.aiSummary') }}</el-tag>
            <el-tag v-else size="small" type="info" effect="plain">{{ t('inspection.ruleSummary') }}</el-tag>
            <span class="text-muted">{{ t('inspection.meta.line', { ms: report.duration_ms, time: fmt(report.created_at), trigger: triggerLabel(report.trigger) }) }}</span>
          </div>
          <div class="summary">{{ report.summary }}</div>
        </div>
      </div>

      <div class="kpi-strip">
        <div class="kpi">
          <div class="kpi-label">{{ t('inspection.kpi.detection') }}</div>
          <div class="kpi-value" :style="{ color: rateColor(m.detection_rate_24h) }">{{ pct(m.detection_rate_24h) }}</div>
          <div class="kpi-sub">{{ t('inspection.kpi.last7', { pct: pct(m.detection_rate_7d) }) }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">{{ t('inspection.kpi.gap') }}</div>
          <div class="kpi-value" :style="{ color: m.gap_ips_24h ? 'var(--el-color-warning)' : 'var(--el-color-success)' }">
            {{ m.gap_ips_24h ?? '—' }}<span class="unit">{{ t('inspection.kpi.unitIp') }}</span>
          </div>
          <div class="kpi-sub">{{ t('inspection.kpi.gapSub', { detected: m.detected_ips_24h ?? 0, blocked: m.blocked_ips_24h ?? 0, exempt: m.exempt_ips_24h ?? 0 }) }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">{{ t('inspection.kpi.blocks') }}</div>
          <div class="kpi-value">{{ m.blocked_24h ?? 0 }}</div>
          <div class="kpi-sub">
            {{ t('inspection.kpi.peak', { hour: m.peak_hour || '—' }) }}<span v-if="m.peak_hour">{{ t('inspection.kpi.peakCount', { n: m.peak_count }) }}</span>
          </div>
        </div>
        <div class="kpi">
          <div class="kpi-label">{{ t('inspection.kpi.persistent') }}</div>
          <div class="kpi-value" :style="{ color: m.persistent_ips ? 'var(--el-color-warning)' : 'var(--el-color-success)' }">
            {{ m.persistent_ips ?? 0 }}<span class="unit">{{ t('inspection.kpi.unitIp') }}</span>
          </div>
          <div class="kpi-sub">{{ t('inspection.kpi.persistentSub') }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">{{ t('inspection.kpi.sources') }}</div>
          <div class="kpi-value" :style="{ color: (m.missing_sources || []).length ? 'var(--el-color-warning)' : 'var(--el-color-success)' }">
            {{ m.core_sources ?? m.active_sources ?? 0 }}<span class="unit">{{ t('inspection.kpi.sourcesUnit') }}</span>
          </div>
          <div class="kpi-sub">{{ (m.missing_sources || []).length ? t('inspection.kpi.sourcesMissing', { list: m.missing_sources.join(' / ') }) : t('inspection.kpi.sourcesOk') }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">{{ t('inspection.kpi.delta') }}</div>
          <div class="kpi-value" :style="{ color: deltaColor }">{{ deltaText }}</div>
          <div class="kpi-sub">{{ m.previous_score != null ? t('inspection.kpi.deltaPrev', { score: m.previous_score }) : t('inspection.kpi.deltaFirst') }}</div>
        </div>
      </div>
    </div>
    <el-empty v-else-if="!loading" :description="t('inspection.empty')" style="margin-top: 60px" />

    <div v-if="report" class="check-grid">
      <div v-for="c in report.checks" :key="c.key" class="check-card" :class="'check-' + c.status">
        <div class="check-head">
          <span class="check-icon">{{ STATUS_ICON[c.status] }}</span>
          <span class="check-name">{{ c.name }}</span>
          <el-tag size="small" :type="statusTag(c.status)" effect="plain">{{ statusLabelOf(c.status) }}</el-tag>
        </div>
        <!-- 巡检结论由后端生成（P4 才做服务端双语），这里保持原样 -->
        <div class="check-summary">{{ c.summary }}</div>
        <div v-if="c.advice" class="check-advice">💡 {{ c.advice }}</div>

        <!-- 封禁缺口：原因归因 + 高频缺口 IP -->
        <div v-if="c.key === 'gap' && (c.data.reasons || []).length" class="check-detail">
          <div v-for="r in c.data.reasons" :key="r.key" class="detail-row">
            <span class="dot" :class="r.exempt ? 'dot-gray' : 'dot-warn'"></span>
            <span class="detail-name">{{ r.label }}</span>
            <span class="detail-num">{{ r.ip_count }} IP / {{ r.alert_count }}</span>
            <el-tag v-if="r.exempt" size="small" type="info" effect="plain">{{ t('inspection.check.exempt') }}</el-tag>
          </div>
          <div v-if="(c.data.top_gaps || []).length" class="sample-list">
            <div v-for="g in c.data.top_gaps.slice(0, 3)" :key="g.ip" class="mono">
              {{ t('inspection.check.ipLine', { ip: g.ip, country: g.country ? '· ' + g.country : '', n: g.count, label: g.label }) }}
            </div>
          </div>
        </div>

        <!-- 三流覆盖 -->
        <div v-if="c.key === 'sources' && (c.data.items || []).length" class="src-chips">
          <span v-for="s in c.data.items" :key="s.source" class="src-chip">
            <b>{{ s.source }}</b> {{ s.alerts }}<span class="text-muted"> / {{ s.blocked }}</span>
          </span>
        </div>

        <!-- 处置率 7 日趋势 -->
        <div v-if="c.key === 'detection' && (c.data.series || []).length" class="spark">
          <div v-for="d in c.data.series" :key="d.date" class="spark-col"
               :title="t('inspection.sparkTitle', { date: d.date, rate: pct(d.rate), blocked: d.blocked, detected: d.detected, exempt: d.exempt })">
            <div class="spark-bar" :style="{ height: barHeight(d.rate), background: rateColor(d.rate) }"></div>
            <span class="spark-date">{{ d.date.slice(5) }}</span>
          </div>
        </div>

        <!-- 跨日持续攻击源 -->
        <div v-if="c.key === 'persistent' && (c.data.items || []).length" class="check-detail">
          <div v-for="p in c.data.items" :key="p.ip" class="mono">
            {{ t('inspection.check.persistentLine', { ip: p.ip, days: p.days, hits: p.hits, hours: p.suggest_hours }) }}
          </div>
        </div>

        <div v-if="c.key === 'attacks' && c.data && (c.data.repeat_offenders || []).length" class="check-detail">
          <div v-for="r in c.data.repeat_offenders" :key="r.ip" class="mono">⚠ {{ t('inspection.check.repeat', { ip: r.ip, n: r.count }) }}</div>
        </div>
        <div v-if="c.key === 'devices' && c.data && (c.data.offline || []).length" class="check-detail">
          <div v-for="d in c.data.offline" :key="d.device" class="mono">✗ {{ t('inspection.check.offline', { device: d.device, plugin: d.plugin, message: d.message }) }}</div>
        </div>
      </div>
    </div>

    <div class="table-card" style="margin-top: 16px">
      <div class="card-title">{{ t('inspection.history.title') }}</div>
      <el-table :data="history" size="small" stripe @row-click="showReport">
        <el-table-column prop="created_at" :label="t('inspection.history.time')" width="170">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="score" :label="t('inspection.history.score')" width="120">
          <template #default="{ row }">
            <span :style="{ color: row.score >= 80 ? 'var(--el-color-success)' : row.score >= 55 ? 'var(--el-color-warning)' : 'var(--el-color-danger)', fontWeight: 600 }">{{ row.score }}</span>
            <span v-if="row.metrics && row.metrics.score_delta != null" class="delta"
                  :style="{ color: deltaColorOf(row.metrics.score_delta) }">
              {{ signed(row.metrics.score_delta) }}
            </span>
          </template>
        </el-table-column>
        <el-table-column :label="t('inspection.history.rate')" width="120">
          <template #default="{ row }">
            <span v-if="row.metrics && row.metrics.detection_rate_24h != null"
                  :style="{ color: rateColor(row.metrics.detection_rate_24h) }">
              {{ pct(row.metrics.detection_rate_24h) }}
            </span>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('inspection.history.gap')" width="90">
          <template #default="{ row }">
            <span v-if="row.metrics">{{ row.metrics.gap_ips_24h ?? '—' }}</span>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>
        <el-table-column prop="overall" :label="t('inspection.history.overall')" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="overallTag(row.overall)">{{ overallLabel(row.overall) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="trigger" :label="t('inspection.history.trigger')" width="100">
          <template #default="{ row }">{{ triggerLabel(row.trigger) }}</template>
        </el-table-column>
        <el-table-column prop="summary" :label="t('inspection.history.summary')" min-width="280" show-overflow-tooltip />
        <el-table-column prop="created_by" :label="t('inspection.history.operator')" width="100" />
      </el-table>
      <div class="pager">
        <el-pagination background layout="total, prev, pager, next" :total="total"
                       :page-size="query.page_size" :current-page="query.page"
                       @current-change="(p) => { query.page = p; loadHistory() }" />
      </div>
    </div>

    <el-dialog v-model="detailVisible" :title="t('inspection.detail.title')" width="820px">
      <template v-if="detail">
        <div class="detail-head">
          <el-tag :type="overallTag(detail.overall)" effect="dark">{{ t('inspection.detail.tag', { overall: overallLabel(detail.overall), score: detail.score }) }}</el-tag>
          <span class="text-muted">{{ fmt(detail.created_at) }} · {{ detail.duration_ms }} ms</span>
          <span v-if="detail.metrics && detail.metrics.detection_rate_24h != null" class="text-muted">
            · {{ t('inspection.detail.line', { rate: pct(detail.metrics.detection_rate_24h), gap: detail.metrics.gap_ips_24h }) }}
          </span>
        </div>
        <div class="summary" style="margin: 12px 0">{{ detail.summary }}</div>
        <el-collapse>
          <el-collapse-item v-for="c in detail.checks" :key="c.key" :name="c.key">
            <template #title>
              <span style="margin-right: 8px">{{ STATUS_ICON[c.status] }}</span>
              <b>{{ c.name }}</b>
              <el-tag size="small" :type="statusTag(c.status)" effect="plain" style="margin-left: 8px">{{ statusLabelOf(c.status) }}</el-tag>
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
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const { t, te } = useI18n()
const report = ref(null)
const history = ref([])
const total = ref(0)
const loading = ref(false)
const running = ref(false)
const detail = ref(null)
const detailVisible = ref(false)
const query = reactive({ page: 1, page_size: 10 })

const OVERALL_TAG = { ok: 'success', warn: 'warning', fail: 'danger' }
const STATUS_ICON = { ok: '✅', warn: '⚠️', fail: '❌' }
const STATUS_TAG = { ok: 'success', warn: 'warning', fail: 'danger' }
const scoreColor = (p) => (p >= 80 ? '#67c23a' : p >= 55 ? '#e6a23c' : '#f56c6c')

const m = computed(() => (report.value && report.value.metrics) || {})

function pick(namespace, value, fallback = '-') {
  if (!value) return fallback
  const key = `${namespace}.${value}`
  return te(key) ? t(key) : value
}
const overallLabel = (v) => pick('inspection.overall', v)
const overallTag = (v) => OVERALL_TAG[v] || 'info'
const statusLabelOf = (v) => pick('inspection.status', v)
const statusTag = (v) => STATUS_TAG[v] || 'info'
const triggerLabel = (v) => (v === 'cron' ? t('inspection.meta.cron') : t('inspection.meta.manual'))

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
    ElMessage.success(t('inspection.toast.done', { score: report.value.score, overall: overallLabel(report.value.overall) }))
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
