<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h2 class="page-title">{{ t('logSources.title') }}</h2>
        <p class="page-desc">{{ t('logSources.desc') }}</p>
      </div>
      <div class="head-actions">
        <el-button :icon="Connection" @click="openMcp">{{ t('logSources.mcp.configure') }}</el-button>
        <el-button :icon="List" @click="openStreams" :loading="loadingStreams">
          {{ t('logSources.stream.fromGraylog') }}
        </el-button>
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
          <el-button size="small" type="primary" @click="openMcp">{{ t('logSources.mcp.configureNow') }}</el-button>
          <el-button size="small" @click="$router.push('/patrol')">{{ t('logSources.mcp.goPatrol') }}</el-button>
        </div>
      </template>
    </el-alert>

    <div v-else-if="data.mcp.url" class="mcp-bar">
      <span class="mcp-dot"></span>
      <span class="mono">{{ data.mcp.url }}</span>
      <span class="text-muted">{{ t('logSources.mcp.modeInline', { mode: data.mcp.mode || '-' }) }}</span>
      <el-button link size="small" @click="openMcp">{{ t('logSources.mcp.edit') }}</el-button>
    </div>

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

        <el-table-column :label="t('logSources.col.actions')" width="170" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" :disabled="!isAdmin" @click="openEdit(row)">
              {{ t('logSources.action.edit') }}
            </el-button>
            <el-button link type="warning" size="small" :disabled="!isAdmin" @click="openProbe(row)">
              {{ t('logSources.action.probe') }}
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
          <el-select
            v-model="form.stream_id"
            filterable allow-create default-first-option clearable
            style="width: 100%"
            :placeholder="t('logSources.form.streamPlaceholder')"
            :loading="loadingStreams"
            :no-data-text="streamHint || t('logSources.stream.empty')"
            @visible-change="onStreamDropdown"
            @change="onStreamPick"
          >
            <el-option v-for="s in streamOptions" :key="s.id" :label="s.title" :value="s.id">
              <div class="opt-row">
                <span class="opt-title">{{ s.title }}</span>
                <el-tag
                  v-if="s.suggested && s.suggested === suggestedRole"
                  size="small" type="success" effect="plain"
                >{{ t('logSources.stream.suggested') }}</el-tag>
                <span class="opt-id mono">{{ s.id }}</span>
              </div>
            </el-option>
          </el-select>
          <div class="form-hint">{{ t('logSources.form.streamIdHint') }}</div>
          <div class="form-hint stream-hint">
            <span>{{ streamHint }}</span>
            <a v-if="mcpReady" class="link" @click.prevent="loadStreams(true)">
              {{ loadingStreams ? t('logSources.stream.loading') : t('logSources.stream.refresh') }}
            </a>
          </div>
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
          <div v-if="missingBlocking.length" class="field-warn">
            {{ t('logSources.form.missingBlocking', { fields: missingBlocking.join(', ') }) }}
          </div>
          <div v-if="fieldStatus.length" class="field-status">
            <div v-for="st in fieldStatus" :key="st.field" class="field-chip">
              <el-tag size="small"
                :type="st.level === 'blocking' ? 'danger' : (st.level === 'suggested' ? 'warning' : 'info')">
                {{ st.field }}
              </el-tag>
              <span class="mono">→ {{ st.graylog }}</span>
              <span class="dim">（{{ t('logSources.form.how_' + st.how) }}）{{ st.label }}</span>
            </div>
          </div>
        </el-form-item>

        <el-form-item :label="t('logSources.form.fieldMapping')">
          <div class="mapping-box">
            <div v-for="(m, i) in form.field_mapping" :key="i" class="mapping-row">
              <el-select
                v-model="m.k" filterable allow-create default-first-option
                :placeholder="t('logSources.form.mapPlatform')" class="mono mapping-input"
              >
                <el-option v-for="f in fieldOptions" :key="f" :label="f" :value="f" />
              </el-select>
              <span class="mapping-arrow">→</span>
              <el-input
                v-model="m.v" maxlength="64" class="mono mapping-input"
                :placeholder="t('logSources.form.mapGraylog')"
              />
              <el-button link type="danger" size="small" @click="form.field_mapping.splice(i, 1)">
                {{ t('logSources.form.mapRemove') }}
              </el-button>
            </div>
            <el-button size="small" @click="form.field_mapping.push({ k: '', v: '' })">
              + {{ t('logSources.form.mapAdd') }}
            </el-button>
            <div class="form-hint">{{ t('logSources.form.mappingHint') }}</div>
          </div>
        </el-form-item>

        <el-form-item :label="t('logSources.form.valueMapping')">
          <div class="mapping-box">
            <div v-for="(g, gi) in form.value_mapping" :key="gi" class="mapping-group">
              <div class="mapping-group-head">
                <el-select
                  v-model="g.field" filterable allow-create default-first-option
                  :placeholder="t('logSources.form.vmField')" class="mono mapping-input"
                >
                  <el-option v-for="f in valueFieldOptions" :key="f" :label="f" :value="f" />
                </el-select>
                <el-button link type="danger" size="small"
                           @click="form.value_mapping.splice(gi, 1)">
                  {{ t('logSources.form.mapRemove') }}
                </el-button>
              </div>
              <div v-for="(r, ri) in g.rows" :key="ri" class="mapping-row">
                <el-input v-model="r.raw" maxlength="64" class="mono mapping-input"
                          :placeholder="t('logSources.form.vmRaw')" />
                <span class="mapping-arrow">→</span>
                <el-select v-model="r.canon" filterable allow-create class="mono mapping-input"
                           :placeholder="t('logSources.form.vmCanon')">
                  <el-option v-for="c in ACTION_VOCAB" :key="c" :label="c" :value="c" />
                </el-select>
                <el-button link type="danger" size="small" @click="g.rows.splice(ri, 1)">
                  {{ t('logSources.form.mapRemove') }}
                </el-button>
              </div>
              <el-button size="small" @click="g.rows.push({ raw: '', canon: '' })">
                + {{ t('logSources.form.vmAddValue') }}
              </el-button>
            </div>
            <el-button size="small" @click="form.value_mapping.push({ field: '', rows: [{ raw: '', canon: '' }] })">
              + {{ t('logSources.form.vmAddField') }}
            </el-button>
            <div class="form-hint">{{ t('logSources.form.vmHint') }}</div>
          </div>
        </el-form-item>

        <el-form-item :label="t('logSources.form.ipWhitelist')">
          <el-input
            v-model="form.ip_whitelist_text" type="textarea" :rows="2" class="mono"
            :placeholder="t('logSources.form.whitelistHint')"
          />
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

    <el-dialog v-model="streamDialog.open" :title="t('logSources.stream.fromGraylog')" width="720px">
      <p class="dialog-desc">{{ t('logSources.stream.dialogHint') }}</p>
      <el-table :data="streamOptions" size="small" max-height="420" :empty-text="streamHint">
        <el-table-column :label="t('logSources.stream.col.title')" min-width="180" prop="title" />
        <el-table-column :label="t('logSources.stream.col.id')" min-width="220">
          <template #default="{ row }">
            <span class="mono" style="font-size: 12px">{{ row.id }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('logSources.stream.col.suggested')" width="110">
          <template #default="{ row }">
            <el-tag v-if="row.suggested" size="small" effect="plain">{{ row.suggested }}</el-tag>
            <span v-else class="text-muted">-</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('logSources.stream.col.desc')" min-width="180">
          <template #default="{ row }">
            <span class="text-muted" style="font-size: 12px">{{ row.description || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column width="72" align="right">
          <template #default="{ row }">
            <el-button link size="small" @click="copyId(row.id)">{{ t('logSources.stream.copy') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-collapse v-if="!streamOptions.length && streamAttempts.length" class="diag-box">
        <el-collapse-item :title="t('logSources.stream.diagTitle')" name="diag">
          <p class="dialog-desc">{{ t('logSources.stream.diagHint') }}</p>
          <div v-for="(a, i) in streamAttempts" :key="i" class="diag-row">
            <span :class="['diag-dot', a.ok ? 'ok' : 'fail']"></span>
            <span class="diag-step">{{ a.step }}</span>
            <span v-if="a.ok" class="diag-count">→ {{ a.count }}</span>
            <span v-else-if="a.detail" class="diag-err">{{ a.detail }}</span>
            <div v-if="a.raw" class="diag-raw">{{ a.raw }}</div>
          </div>
        </el-collapse-item>
      </el-collapse>
      <template #footer>
        <el-button size="small" :loading="loadingStreams" @click="loadStreams(true)">
          {{ loadingStreams ? t('logSources.stream.loading') : t('logSources.stream.refresh') }}
        </el-button>
        <el-button size="small" type="primary" @click="streamDialog.open = false">
          {{ t('common.action.close') }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="mcpDialog.open" :title="t('logSources.mcp.title')" width="600px">
      <el-alert
        v-if="mcpDialog.info && !mcpDialog.info.error && mcpDialog.info.server && mcpDialog.info.server.name"
        type="success" show-icon :closable="false" style="margin-bottom: 12px"
        :title="t('logSources.mcp.connected', { name: mcpDialog.info.server.name, ver: mcpDialog.info.server.version || '-' })"
      />
      <el-alert
        v-else-if="mcpDialog.info && mcpDialog.info.error"
        type="error" show-icon :closable="false" style="margin-bottom: 12px"
        :title="mcpDialog.info.error"
      />
      <el-form label-position="top" size="small">
        <el-form-item :label="t('logSources.mcp.url')" required>
          <el-input v-model="mcpForm.mcp_url" clearable placeholder="https://graylog.example.com/api/mcp" class="mono" />
          <div class="form-hint">{{ t('logSources.mcp.urlHint') }}</div>
        </el-form-item>
        <el-form-item :label="t('logSources.mcp.token')">
          <el-input
            v-model="mcpForm.mcp_token" type="password" show-password clearable
            :placeholder="mcpTokenSet ? t('logSources.mcp.tokenSet', { hint: mcpTokenHint || '-' }) : t('logSources.mcp.tokenPlaceholder')"
          />
          <div class="form-hint">{{ t('logSources.mcp.tokenHint') }}</div>
        </el-form-item>
        <el-form-item :label="t('logSources.mcp.auth')">
          <el-select v-model="mcpForm.mcp_auth" style="width: 100%">
            <el-option value="token" :label="t('logSources.mcp.authToken')" />
            <el-option value="bearer" :label="t('logSources.mcp.authBearer')" />
            <el-option value="basic" :label="t('logSources.mcp.authBasic')" />
            <el-option value="raw" :label="t('logSources.mcp.authRaw')" />
            <el-option value="none" :label="t('logSources.mcp.authNone')" />
          </el-select>
        </el-form-item>
      </el-form>
      <div class="form-hint">
        {{ mcpDialog.source === 'db' ? t('logSources.mcp.sourceDb') : t('logSources.mcp.sourceEnv') }}
        · {{ t('logSources.mcp.plainHint') }}
      </div>
      <template #footer>
        <el-button size="small" :loading="mcpTesting" @click="testMcp(false)">
          {{ mcpTesting ? t('logSources.mcp.testing') : t('logSources.mcp.test') }}
        </el-button>
        <el-button size="small" @click="mcpDialog.open = false">{{ t('common.action.close') }}</el-button>
        <el-button size="small" type="primary" :loading="mcpSaving" @click="saveMcp">
          {{ t('logSources.form.save') }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="probe.open" :title="t('logSources.probe.title', { name: probe.label })" width="700px" destroy-on-close>
      <div v-loading="probe.loading" style="min-height: 120px">
        <template v-if="probe.data">
          <el-alert v-if="probe.data.error" type="error" show-icon :closable="false"
                    :title="probe.data.error" style="margin-bottom: 12px" />
          <el-descriptions v-else :column="3" size="small" border>
            <el-descriptions-item :label="t('logSources.probe.tool')">
              <span class="mono">{{ probe.data.tool }}</span>
            </el-descriptions-item>
            <el-descriptions-item :label="t('logSources.probe.fetched')">
              <b>{{ probe.data.fetched }}</b>
            </el-descriptions-item>
            <el-descriptions-item :label="t('logSources.probe.control')">
              {{ probe.data.control.fetched }}
            </el-descriptions-item>
          </el-descriptions>

          <p v-if="probeHint" class="dialog-desc" style="margin: 10px 0 0">{{ probeHint }}</p>

          <h4 class="probe-title">{{ t('logSources.probe.args') }}</h4>
          <pre class="code-block">{{ pretty(probe.data.arguments) }}</pre>

          <template v-if="probeSchema">
            <h4 class="probe-title">{{ t('logSources.probe.schema') }}</h4>
            <pre class="code-block">{{ probeSchema }}</pre>
          </template>

          <h4 class="probe-title">{{ t('logSources.probe.raw') }}</h4>
          <pre class="code-block">{{ probe.data.raw || t('logSources.probe.emptyRaw') }}</pre>
        </template>
      </div>
      <template #footer>
        <el-button size="small" :loading="probe.loading" @click="runProbe(probe.row)">{{ t('logSources.probe.again') }}</el-button>
        <el-button size="small" @click="probe.open = false">{{ t('common.action.close') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Refresh, List, Connection } from '@element-plus/icons-vue'
import api from '../api'
import { store } from '../store'

const { t } = useI18n()

const loading = ref(false)
const saving = ref(false)
const verifying = ref(false)
const drawer = reactive({ open: false, row: null, title: '' })
const form = reactive({
  label: '', stream_id: '', query: '', schema_version: '1.0',
  required_fields: [], field_mapping: [], value_mapping: [], purpose: [], enabled: true,
})
// 平台标准动作词表：规则只认这些值，厂商枚举在值映射里翻过来
const ACTION_VOCAB = ['observe', 'audit', 'block', 'ban', 'pass', 'reject']
const valueFieldOptions = ['action', 'severity', 'waf_action', 'ips_action']
const data = reactive({ mcp: {}, items: [], summary: {}, spec: {} })

// ---- 必填字段校验（与后端 patrol_settings.validate_required_fields 同口径）----
// 阻断项：ts/src_ip 缺失保存会被后端 400 拒绝；其余按源给出建议提示
const BLOCKING_FIELDS = ['ts', 'src_ip']
const SUGGESTED_BY_SOURCE = {
  ips: ['action', 'severity'], waf: ['action', 'url'],
  ztna: ['username', 'display_name', 'ua_class', 'dst_domain', 'l7_app_request_type'],
}
const FIELD_LABELS = {
  ts: '日志时间', src_ip: '来源IP', action: '动作', severity: '级别', url: '请求路径',
  status_code: '状态码', ua_raw: 'User-Agent', ua_class: '设备类型', username: '账号',
  display_name: '显示名', l7_app_request_type: '请求类型', dst_domain: '目标域名',
}
const FIELD_ALIASES = { ts: 'timestamp', src: 'source' }   // 与后端 REQUEST_FIELD_ALIASES 同步

const fieldStatus = computed(() => {
  const mapping = Object.fromEntries((form.field_mapping || [])
    .filter((m) => m.k && m.v).map((m) => [m.k.trim(), m.v.trim()]))
  const suggested = SUGGESTED_BY_SOURCE[drawer.row?.source_code] || []
  return (form.required_fields || []).map((f) => {
    const graylog = mapping[f] || FIELD_ALIASES[f] || f
    const how = mapping[f] ? 'mapping' : (FIELD_ALIASES[f] ? 'alias' : 'same')
    const level = BLOCKING_FIELDS.includes(f) ? 'blocking'
      : (suggested.includes(f) ? 'suggested' : 'optional')
    return { field: f, graylog, how, level, label: FIELD_LABELS[f] || '' }
  })
})
const missingBlocking = computed(() =>
  BLOCKING_FIELDS.filter((f) => !(form.required_fields || []).includes(f)))

// Graylog 流清单：进入下拉时懒加载一次，之后复用；「刷新清单」可强制重取。
// 读的是 MCP 的 list_streams（服务端 /patrols/mcp/status 已封装），
// 拿不到就退回手填，不阻塞编辑。
const streamOptions = ref([])
const loadingStreams = ref(false)
const streamsLoaded = ref(false)
const streamHint = ref('')
const streamAttempts = ref([])
const mcpReady = ref(false)
const streamDialog = reactive({ open: false })

// Graylog 接入：地址与 Token 存在巡检配置里（patrol_setting），
// 这里只是把入口搬到数据源页，读写走同一对接口，不另造配置源。
const mcpDialog = reactive({ open: false, info: null, source: '' })
const mcpForm = reactive({ mcp_url: '', mcp_token: '', mcp_auth: 'token' })
const mcpTokenSet = ref(false)
const mcpTokenHint = ref('')
const mcpTesting = ref(false)
const mcpSaving = ref(false)

// 「试取」：对单个源立即打一次 Graylog（不受巡检间隔约束、不落库），
// 把实际发送的参数和服务端原始返回摆出来——「无数据」到底卡在哪一步一看就知道。
const probe = reactive({ open: false, loading: false, row: null, label: '', data: null })
const probeSchema = computed(() => {
  const props = probe.data?.schema?.properties
  if (!props || typeof props !== 'object') return ''
  return Object.entries(props).map(([name, type]) => `${name}: ${type || 'any'}`).join('\n')
})
const probeHint = computed(() => {
  const d = probe.data
  if (!d || d.error) return ''
  if (d.fetched > 0) return t('logSources.probe.hintOk')
  if ((d.control?.fetched || 0) > 0) return t('logSources.probe.hintFiltered')
  return t('logSources.probe.hintEmpty')
})

const ROLE_BY_CODE = { ips: 'IPS', waf: 'WAF', ztna: 'ZTNA' }
const suggestedRole = computed(() => ROLE_BY_CODE[drawer.row?.source_code] || '')

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
  form.field_mapping = Object.entries(row.field_mapping || {})
    .map(([k, v]) => ({ k, v }))
  form.value_mapping = Object.entries(row.value_mapping || {})
    .map(([field, values]) => ({
      field,
      rows: Object.entries(values || {}).map(([raw, canon]) => ({ raw, canon })),
    }))
  form.ip_whitelist_text = (row.ip_whitelist || []).join('\n')
  form.purpose = [...(row.purpose || [])]
  form.enabled = row.enabled !== false
  drawer.open = true
  sortStreams()
}

// 与当前源名匹配的流排最前：Graylog 里几十条流，翻起来太慢
function sortStreams() {
  streamOptions.value = [...streamOptions.value].sort((a, b) => {
    const sa = a.suggested && a.suggested === suggestedRole.value ? 1 : 0
    const sb = b.suggested && b.suggested === suggestedRole.value ? 1 : 0
    return sb - sa
  })
}

async function loadStreams(force = false) {
  if (loadingStreams.value) return
  if (streamsLoaded.value && !force) return
  loadingStreams.value = true
  try {
    const info = await api.patrolMcpStatus()
    if (!info?.configured) {
      mcpReady.value = false
      streamOptions.value = []
      streamAttempts.value = []
      streamHint.value = t('logSources.stream.noMcp')
      return
    }
    mcpReady.value = true
    const list = Array.isArray(info.streams) ? info.streams : []
    streamOptions.value = list
    streamAttempts.value = Array.isArray(info.streams_attempts) ? info.streams_attempts : []
    sortStreams()
    streamsLoaded.value = true
    streamHint.value = list.length
      ? t('logSources.stream.count', { n: list.length })
      : t('logSources.stream.empty')
  } catch (e) {
    // 拦截器已提示；保留手填入口
    streamHint.value = t('logSources.stream.loadFailed')
  } finally {
    loadingStreams.value = false
  }
}

function onStreamDropdown(visible) {
  if (visible) loadStreams()
}

function openStreams() {
  streamDialog.open = true
  loadStreams(true)
}

async function copyId(id) {
  try {
    await navigator.clipboard.writeText(id)
    ElMessage.success(t('logSources.stream.copied'))
  } catch (e) {
    // 非安全上下文（http、内嵌 webview）没有 clipboard API，退回让用户手选
    ElMessage.warning(id)
  }
}

function onStreamPick(id) {
  const hit = streamOptions.value.find((s) => s.id === id)
  if (!hit) return
  if (!form.label.trim()) form.label = hit.title
  // 名字关键词与当前源不符时提醒一句：防止把 ips 的流填进 ztna
  if (hit.suggested && hit.suggested !== suggestedRole.value) {
    ElMessage.warning(t('logSources.stream.mismatch', {
      title: hit.title, source: drawer.row?.name || '',
    }))
  }
}

async function openMcp() {
  mcpDialog.open = true
  mcpDialog.info = null
  mcpForm.mcp_token = ''
  try {
    const cfg = await api.patrolConfig()
    mcpForm.mcp_url = cfg.mcp_url || ''
    mcpForm.mcp_auth = cfg.mcp_auth || 'token'
    mcpTokenSet.value = !!cfg.token_set
    mcpTokenHint.value = cfg.token_hint || ''
    mcpDialog.source = cfg.source || ''
  } catch (e) {
    // 拦截器已提示
  }
  if (mcpForm.mcp_url) testMcp(true)
}

async function testMcp(silent) {
  const url = (mcpForm.mcp_url || '').trim()
  if (!url) {
    if (!silent) ElMessage.warning(t('logSources.mcp.needUrl'))
    return
  }
  mcpTesting.value = true
  try {
    const info = await api.patrolMcpTest({
      mcp_url: url,
      mcp_auth: mcpForm.mcp_auth,
      mcp_token: mcpForm.mcp_token || undefined,
    })
    mcpDialog.info = info
    if (!info?.error) {
      // 地址变了，流清单必须重拉，否则下拉里还是旧 Graylog 的流
      streamsLoaded.value = false
      await loadStreams(true)
    } else if (!silent) {
      ElMessage.error(info.error)
    }
  } catch (e) {
    // 拦截器已提示
  } finally {
    mcpTesting.value = false
  }
}

async function saveMcp() {
  const url = (mcpForm.mcp_url || '').trim()
  if (!url) {
    ElMessage.warning(t('logSources.mcp.needUrl'))
    return
  }
  mcpSaving.value = true
  try {
    // 只传这三个字段：后端 save() 对其余字段用当前值兜底，不会动流映射与节奏
    await api.patrolConfigSave({
      mcp_url: url,
      mcp_auth: mcpForm.mcp_auth,
      ...(mcpForm.mcp_token ? { mcp_token: mcpForm.mcp_token } : {}),
    })
    ElMessage.success(t('logSources.mcp.saved'))
    mcpDialog.open = false
    streamsLoaded.value = false
    streamOptions.value = []
    await load()
  } catch (e) {
    // 拦截器已提示
  } finally {
    mcpSaving.value = false
  }
}

async function save() {
  if (!drawer.row) return
  saving.value = true
  try {
    const mapping = {}
    form.field_mapping.forEach((m) => {
      const k = (m.k || '').trim()
      const v = (m.v || '').trim()
      if (k && v && k !== v) mapping[k] = v
    })
    const value_mapping = {}
    form.value_mapping.forEach((g) => {
      const field = (g.field || '').trim()
      const inner = {}
      g.rows.forEach((r) => {
        const raw = (r.raw || '').trim()
        const canon = (r.canon || '').trim()
        if (field && raw && canon && raw !== canon) inner[raw] = canon
      })
      if (field && Object.keys(inner).length) value_mapping[field] = inner
    })
    const ip_whitelist = form.ip_whitelist_text
      .split(/[\n,]/).map((x) => x.trim()).filter(Boolean)
    await api.logSourceUpdate(drawer.row.source_code, {
      label: form.label,
      stream_id: form.stream_id.trim(),
      query: form.query.trim(),
      schema_version: form.schema_version.trim() || '1.0',
      required_fields: form.required_fields,
      field_mapping: mapping,
      value_mapping,
      ip_whitelist,
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

function pretty(value) {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch (e) {
    return String(value)
  }
}

function openProbe(row) {
  probe.open = true
  probe.row = row
  probe.label = row?.label || row?.name || ''
  probe.data = null
  runProbe(row)
}

async function runProbe(row) {
  if (!row) return
  probe.row = row
  probe.loading = true
  try {
    probe.data = await api.logSourceProbe(row.source_code)
  } catch (e) {
    // 拦截器已提示
  } finally {
    probe.loading = false
  }
}

onMounted(load)
</script>

<style scoped>
.head-actions {
  display: flex;
  gap: 8px;
}
.diag-box {
  margin-top: 10px;
}
.probe-title {
  margin: 14px 0 6px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  font-weight: 600;
}
.code-block {
  margin: 0;
  padding: 10px 12px;
  max-height: 220px;
  overflow: auto;
  background: var(--el-fill-color-light);
  border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
}
.diag-row {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 6px;
  padding: 4px 0;
  font-size: 12px;
  border-bottom: 1px dashed var(--el-border-color-lighter);
}
.diag-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex: none;
}
.diag-dot.ok {
  background: var(--el-color-success);
}
.diag-dot.fail {
  background: var(--el-color-danger);
}
.diag-step {
  font-family: var(--el-font-family-mono, monospace);
  color: var(--el-text-color-regular);
}
.diag-count {
  color: var(--el-color-success);
}
.diag-err {
  color: var(--el-color-danger);
  word-break: break-all;
}
.diag-raw {
  flex-basis: 100%;
  margin: 2px 0 4px 12px;
  padding: 4px 8px;
  background: var(--el-fill-color-lighter);
  border-radius: 4px;
  color: var(--el-text-color-secondary);
  word-break: break-all;
  max-height: 72px;
  overflow: auto;
}
.dialog-desc {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin: 0 0 10px;
  line-height: 1.6;
}
.mcp-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 12px;
  background: var(--el-fill-color-light);
  border-radius: 6px;
  padding: 6px 12px;
  margin-bottom: 12px;
}
.mcp-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--el-color-success);
  flex: none;
}
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
.mapping-box {
  width: 100%;
}
.mapping-group { border: 1px solid var(--el-border-color-lighter); border-radius: 6px; padding: 8px; margin-bottom: 8px; }
.mapping-group-head { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.mapping-group-head .mapping-input { width: 220px; }
.mapping-row {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 6px;
}
.mapping-input {
  width: 180px;
}
.mapping-arrow {
  color: var(--el-text-color-secondary);
}
.field-status {
  width: 100%;
  margin-top: 6px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.field-chip {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
}
.field-warn {
  width: 100%;
  margin-top: 6px;
  color: var(--el-color-danger);
  font-size: 12px;
}
.stream-hint {
  display: flex;
  justify-content: space-between;
  gap: 8px;
}
.stream-hint .link {
  color: var(--el-color-primary);
  cursor: pointer;
  white-space: nowrap;
}
.opt-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.opt-title {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.opt-id {
  font-size: 11px;
  color: var(--el-text-color-secondary);
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
