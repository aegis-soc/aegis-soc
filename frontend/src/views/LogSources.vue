<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h2 class="page-title">{{ t('logSources.title') }}</h2>
        <p class="page-desc">{{ t('logSources.desc') }}</p>
      </div>
      <div>
        <el-button :icon="Refresh" @click="load" :loading="loading">{{ t('common.action.refresh') }}</el-button>
      </div>
    </div>

    <el-alert
      v-if="!data.mcp.configured"
      type="warning" show-icon :closable="false" style="margin-bottom: 16px"
      :title="t('logSources.mcp.unconfigured')"
      :description="t('logSources.mcp.unconfiguredHint')"
    >
      <template #default>
        <div style="margin-top: 6px">
          <el-button size="small" @click="$router.push('/patrol')">{{ t('logSources.mcp.goPatrol') }}</el-button>
        </div>
      </template>
    </el-alert>

    <div class="stat-row">
      <div class="stat-card">
        <div class="stat-label">{{ t('logSources.summary.total') }}</div>
        <div class="stat-value">{{ summary.total }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">{{ t('logSources.summary.configured') }}</div>
        <div class="stat-value">{{ summary.configured }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">{{ t('logSources.summary.abnormal') }}</div>
        <div class="stat-value" :class="{ 'stat-bad': summary.abnormal > 0 }">{{ summary.abnormal }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">{{ t('logSources.summary.fetched') }}</div>
        <div class="stat-value">{{ summary.fetched }}<span class="stat-unit">{{ t('logSources.summary.unit') }}</span></div>
        <div class="stat-hint">
          {{ summary.last_run_at ? t('logSources.summary.lastRun', { time: fmtTime(summary.last_run_at) }) : t('logSources.summary.noRun') }}
        </div>
      </div>
    </div>

    <div class="table-card">
      <el-table :data="data.items" v-loading="loading" size="small" :empty-text="t('logSources.empty')">
        <el-table-column :label="t('logSources.col.source')" min-width="150">
          <template #default="{ row }">
            <div class="src-name">{{ row.label || row.name }}</div>
            <span class="mono text-muted" style="font-size: 11px">{{ row.source_code }}</span>
          </template>
        </el-table-column>

        <el-table-column :label="t('logSources.col.stream')" min-width="180">
          <template #default="{ row }">
            <span v-if="row.stream_id" class="mono" style="font-size: 12px">{{ row.stream_id }}</span>
            <span v-else class="text-muted">{{ t('logSources.state.unconfigured') }}</span>
            <div v-if="row.query" class="mono text-muted" style="font-size: 11px">{{ row.query }}</div>
          </template>
        </el-table-column>

        <el-table-column :label="t('logSources.col.version')" width="90" align="center">
          <template #default="{ row }"><span class="mono">{{ row.schema_version }}</span></template>
        </el-table-column>

        <el-table-column :label="t('logSources.col.purpose')" width="150">
          <template #default="{ row }">
            <el-tag v-for="p in row.purpose" :key="p" size="small" effect="plain" style="margin-right: 4px">
              {{ t(`logSources.purpose.${p}`) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column :label="t('logSources.col.required')" width="110" align="center">
          <template #default="{ row }">
            <el-popover placement="top" width="260" trigger="hover">
              <template #reference>
                <span style="cursor: help">{{ (row.required_fields || []).length }}</span>
              </template>
              <div class="mono" style="font-size: 12px; line-height: 1.8">
                {{ (row.required_fields || []).join(', ') || '-' }}
              </div>
            </el-popover>
          </template>
        </el-table-column>

        <el-table-column :label="t('logSources.col.fetched')" width="90" align="right">
          <template #default="{ row }"><span class="mono">{{ row.health.fetched }}</span></template>
        </el-table-column>

        <el-table-column :label="t('logSources.col.missing')" width="100" align="right">
          <template #default="{ row }">
            <el-popover v-if="row.health.missing_total" placement="top" width="240" trigger="hover">
              <template #reference>
                <span class="mono" :class="{ 'text-danger': row.health.missing_ratio > 0.005 }">
                  {{ pct(row.health.missing_ratio) }}
                </span>
              </template>
              <div class="mono" style="font-size: 12px; line-height: 1.8">
                <div v-for="(n, f) in row.health.missing" :key="f">{{ f }}: {{ n }}</div>
              </div>
            </el-popover>
            <span v-else class="mono text-muted">-</span>
          </template>
        </el-table-column>

        <el-table-column :label="t('logSources.col.schemaBad')" width="100" align="right">
          <template #default="{ row }">
            <span class="mono" :class="{ 'text-danger': row.health.schema_bad_ratio > 0.01 }">
              {{ row.health.schema_bad || '-' }}
            </span>
          </template>
        </el-table-column>

        <el-table-column :label="t('logSources.col.state')" width="110">
          <template #default="{ row }">
            <el-tooltip :content="t(`logSources.stateHint.${row.health.state}`)" placement="top">
              <el-tag size="small" :type="tagType(row.health.state)" effect="light">
                {{ t(`logSources.state.${row.health.state}`) }}
              </el-tag>
            </el-tooltip>
          </template>
        </el-table-column>

        <el-table-column :label="t('logSources.col.lastRun')" width="150">
          <template #default="{ row }">
            <span class="mono text-muted" style="font-size: 12px">{{ fmtTime(row.health.last_run_at) }}</span>
          </template>
        </el-table-column>

        <el-table-column :label="t('logSources.col.actions')" width="120" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" :disabled="!isAdmin" @click="openEdit(row)">
              {{ t('logSources.action.edit') }}
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="table-card" style="margin-top: 16px">
      <h3 style="margin: 0 0 10px; font-size: 14px">{{ t('logSources.spec.title') }}</h3>
      <p class="text-muted" style="font-size: 12px; margin: 0 0 8px">{{ t('logSources.spec.desc') }}</p>
      <p class="text-muted" style="font-size: 12px; margin: 0">
        {{ t('logSources.spec.reject', { stream: 'norm-*-reject' }) }}
      </p>
    </div>

    <el-drawer v-model="drawer.open" :title="drawer.title" size="520px" destroy-on-close>
      <el-form v-if="drawer.row" label-position="top" size="small">
        <el-form-item :label="t('logSources.form.label')">
          <el-input v-model="form.label" maxlength="64" />
        </el-form-item>

        <el-form-item :label="t('logSources.form.streamId')">
          <el-input v-model="form.stream_id" maxlength="64" class="mono" placeholder="65f3a2..." />
          <div class="form-hint">{{ t('logSources.form.streamIdHint') }}</div>
        </el-form-item>

        <el-form-item :label="t('logSources.form.query')">
          <el-input v-model="form.query" maxlength="255" class="mono" placeholder="source_code:ztna" />
          <div class="form-hint">{{ t('logSources.form.queryHint') }}</div>
        </el-form-item>

        <el-form-item :label="t('logSources.form.schemaVersion')">
          <el-input v-model="form.schema_version" maxlength="16" style="width: 140px" class="mono" />
          <div class="form-hint">{{ t('logSources.form.schemaVersionHint') }}</div>
        </el-form-item>

        <el-form-item :label="t('logSources.form.requiredFields')">
          <el-select
            v-model="form.required_fields" multiple filterable allow-create default-first-option
            style="width: 100%"
          >
            <el-option v-for="f in fieldOptions" :key="f" :label="f" :value="f" />
          </el-select>
          <div class="form-hint">{{ t('logSources.form.requiredHint') }}</div>
        </el-form-item>

        <el-form-item :label="t('logSources.form.purpose')">
          <el-checkbox-group v-model="form.purpose">
            <el-checkbox v-for="p in ['lba', 'patrol', 'soar']" :key="p" :value="p">
              {{ t(`logSources.purpose.${p}`) }}
            </el-checkbox>
          </el-checkbox-group>
          <div class="form-hint">{{ t('logSources.form.purposeHint') }}</div>
        </el-form-item>

        <el-form-item :label="t('logSources.form.enabled')">
          <el-switch v-model="form.enabled" />
          <div class="form-hint">{{ t('logSources.form.enabledHint') }}</div>
        </el-form-item>
      </el-form>

      <template #footer>
        <div class="drawer-foot">
          <el-button size="small" :loading="verifying" @click="verifyStream(drawer.row)">
            {{ verifying ? t('logSources.action.verifying') : t('logSources.action.verify') }}
          </el-button>
          <div>
            <el-button size="small" @click="drawer.open = false">{{ t('logSources.form.cancel') }}</el-button>
            <el-button size="small" type="primary" :loading="saving" @click="save">{{ t('logSources.form.save') }}</el-button>
          </div>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import api from '../api'
import { store } from '../store'

const { t } = useI18n()

const loading = ref(false)
const saving = ref(false)
const verifying = ref(false)
const drawer = reactive({ open: false, row: null, title: '' })
const form = reactive({
  label: '', stream_id: '', query: '', schema_version: '1.0',
  required_fields: [], purpose: [], enabled: true,
})
const data = reactive({ mcp: {}, items: [], summary: {}, spec: {} })

const isAdmin = computed(() => store.role === 'admin')
const summary = computed(() => data.summary || {})
const fieldOptions = computed(() => {
  const set = new Set(['ts', 'ingest_ts', 'src_ip', 'dst_ip', 'username', 'url', 'url_query',
    'method', 'status_code', 'ua_raw', 'ua_class', 'ua_browser', 'ua_browser_ver', 'ua_os',
    'app_id', 'gateway_node', 'action', 'severity', 'threat_type', 'rule_id'])
  ;(drawer.row?.required_fields || []).forEach((f) => set.add(f))
  return Array.from(set)
})

function tagType(state) {
  if (state === 'ok') return 'success'
  if (state === 'degraded') return 'warning'
  if (state === 'failed') return 'danger'
  return 'info'
}

function pct(value) {
  return `${((value || 0) * 100).toFixed(2)}%`
}

function fmtTime(value) {
  if (!value) return '-'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return d.toLocaleString(store.locale === 'en-US' ? 'en-US' : 'zh-CN', { hour12: false })
}

async function load() {
  loading.value = true
  try {
    const res = await api.logSources()
    Object.assign(data, res || {})
  } catch (e) {
    // 拦截器已提示
  } finally {
    loading.value = false
  }
}

function openEdit(row) {
  drawer.row = row
  drawer.title = t('logSources.form.title', { name: row.label || row.name })
  form.label = row.label || ''
  form.stream_id = row.stream_id || ''
  form.query = row.query || ''
  form.schema_version = row.schema_version || '1.0'
  form.required_fields = [...(row.required_fields || [])]
  form.purpose = [...(row.purpose || [])]
  form.enabled = row.enabled !== false
  drawer.open = true
}

async function save() {
  if (!drawer.row) return
  saving.value = true
  try {
    await api.logSourceUpdate(drawer.row.source_code, {
      label: form.label,
      stream_id: form.stream_id.trim(),
      query: form.query.trim(),
      schema_version: form.schema_version.trim() || '1.0',
      required_fields: form.required_fields,
      purpose: form.purpose,
      enabled: form.enabled,
    })
    ElMessage.success(t('logSources.form.saved'))
    drawer.open = false
    await load()
  } catch (e) {
    // 拦截器已提示
  } finally {
    saving.value = false
  }
}

async function verifyStream(row) {
  if (!row) return
  verifying.value = true
  try {
    const info = await api.patrolMcpStatus()
    if (!info?.configured) {
      ElMessage.warning(t('logSources.action.verifyNoMcp'))
      return
    }
    const hit = (info.configured_streams || []).find(
      (s) => String(s.name || '').toUpperCase() === String(row.name).toUpperCase(),
    )
    const streamId = (form.stream_id || '').trim()
    if (!streamId) {
      ElMessage.warning(t('logSources.state.unconfigured'))
      return
    }
    // Graylog 的流清单只对「已保存的」stream_id 做比对：表单里改了新 ID 时
    // 直接校验会得出错误结论，先要求保存。
    if (!hit || hit.stream_id !== streamId) {
      ElMessage.warning(t('logSources.action.verifySaveFirst'))
      return
    }
    if (hit.exists === null || hit.exists === undefined) {
      ElMessage.warning(t('logSources.action.verifyNoMcp'))
      return
    }
    if (hit.exists === false) ElMessage.error(t('logSources.action.verifyMissing'))
    else ElMessage.success(t('logSources.action.verifyOk'))
  } catch (e) {
    // 拦截器已提示
  } finally {
    verifying.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.stat-row {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
  margin-bottom: 16px;
}
.stat-card {
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 8px;
  padding: 14px 16px;
}
.stat-label {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-bottom: 8px;
}
.stat-value {
  font-size: 26px;
  font-weight: 500;
  line-height: 1.1;
  color: var(--el-text-color-primary);
}
.stat-bad {
  color: var(--el-color-danger);
}
.stat-unit {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-left: 4px;
}
.stat-hint {
  margin-top: 6px;
  font-size: 11px;
  color: var(--el-text-color-secondary);
}
.src-name {
  font-size: 13px;
  font-weight: 500;
}
.form-hint {
  font-size: 11px;
  color: var(--el-text-color-secondary);
  line-height: 1.6;
  margin-top: 4px;
}
.text-danger {
  color: var(--el-color-danger);
}
.drawer-foot {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.mono {
  font-family: var(--el-font-family-mono, ui-monospace, SFMono-Regular, Menlo, monospace);
}
</style>
