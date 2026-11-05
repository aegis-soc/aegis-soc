<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">设备管理</h2><p class="page-desc">选择插件后自动生成配置表单；地址、业务参数、凭据分开填写，凭据只存环境变量名</p></div>
      <el-button type="primary" :icon="Plus" @click="openCreate">新增设备</el-button>
    </div>

    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="device_code" label="设备编码" width="150" class-name="mono" />
        <el-table-column prop="name" label="名称" min-width="140" />
        <el-table-column prop="plugin_code" label="插件" width="130" />
        <el-table-column label="设备地址" min-width="190">
          <template #default="{ row }"><span class="mono">{{ addressOf(row) }}</span></template>
        </el-table-column>
        <el-table-column prop="vendor" label="厂商" width="110" />
        <el-table-column prop="region" label="区域" width="100" />
        <el-table-column prop="status" label="状态" width="90">
          <template #default="{ row }"><el-tag size="small" :type="row.status === 'online' ? 'success' : 'info'">{{ row.status }}</el-tag></template>
        </el-table-column>
        <el-table-column label="自动下发" width="90">
          <template #default="{ row }">{{ row.auto_dispatch ? '是' : '否' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="210" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="test(row)">连通性测试</el-button>
            <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-popconfirm title="确认删除该设备？" @confirm="remove(row)">
              <template #reference><el-button link type="danger">删除</el-button></template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="dialog" :title="editing ? '编辑设备' : '新增设备'" width="720px" top="5vh">
      <el-form :model="form" label-width="120px">
        <el-form-item label="设备编码" required>
          <el-input v-model="form.device_code" :disabled="!!editing" placeholder="如 fw-hq-01" />
        </el-form-item>
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="如 总部出口防火墙" />
        </el-form-item>
        <el-form-item label="插件" required>
          <el-select v-model="form.plugin_code" :disabled="!!editing" style="width: 100%" @change="onPluginChange">
            <el-option v-for="p in plugins" :key="p.plugin_code" :label="`${p.plugin_name}（${p.plugin_code}）`" :value="p.plugin_code" />
          </el-select>
          <div v-if="currentPlugin?.description" class="field-hint">{{ currentPlugin.description }}</div>
        </el-form-item>

        <template v-if="currentPlugin">
          <div class="form-switch">
            <el-switch v-model="advanced" active-text="高级模式（直接编辑 JSON）" @change="toggleAdvanced" />
          </div>

          <div v-if="advanced" class="advanced-box">
            <el-input v-model="configText" type="textarea" :rows="10" class="mono" spellcheck="false" />
            <div class="field-hint">整段 JSON 会原样保存；分层的 connection / params 写法与扁平写法都支持。</div>
          </div>

          <template v-else>
            <div v-for="(f, i) in fields" :key="f.key">
              <div v-if="i === 0 || fields[i - 1].group !== f.group" class="group-title">
                {{ f.group === 'connection' ? '① 设备连接' : '② 业务参数' }}
              </div>
              <el-form-item :label="f.label" :required="f.required">
                <div class="field-wrap">
                  <el-switch v-if="f.type === 'bool'" v-model="values[f.key]" />
                  <el-input-number
                    v-else-if="f.type === 'int' || f.type === 'float'"
                    v-model="values[f.key]" :min="0" :controls="false" :placeholder="placeholderOf(f)" style="width: 100%"
                  />
                  <el-select v-else-if="f.type === 'enum'" v-model="values[f.key]" clearable style="width: 100%" :placeholder="placeholderOf(f)">
                    <el-option v-for="o in f.options" :key="o" :label="o" :value="o" />
                  </el-select>
                  <el-input
                    v-else-if="f.type === 'object'" v-model="values[f.key]" type="textarea" :rows="3" class="mono" :placeholder="placeholderOf(f)"
                  />
                  <el-input v-else v-model="values[f.key]" :placeholder="placeholderOf(f)" :class="{ mono: f.address }" />
                  <div class="field-hint">{{ hintOf(f) }}</div>
                </div>
              </el-form-item>
            </div>

            <el-form-item label="凭据环境变量">
              <el-input v-model="form.credential_ref" :placeholder="currentPlugin.manifest?.credential_hint || '如 FW_PASSWORD'" />
              <div class="field-hint">
                填<b>变量名</b>，不是口令本身。在服务器 .env 里设置
                <code class="mono">{{ form.credential_ref || currentPlugin.manifest?.credential_hint || 'XXX_CRED' }}</code>
                后重启 api 与 worker。
              </div>
            </el-form-item>
          </template>
        </template>

        <el-form-item label="厂商"><el-input v-model="form.vendor" /></el-form-item>
        <el-form-item label="区域"><el-input v-model="form.region" /></el-form-item>
        <el-form-item label="允许自动下发"><el-switch v-model="form.auto_dispatch" /></el-form-item>

        <el-alert
          v-if="dialogTest.message" :type="dialogTest.success ? 'success' : 'error'" :closable="false"
          :title="dialogTest.message" style="margin-bottom: 8px"
        />
      </el-form>

      <template #footer>
        <div class="dialog-footer">
          <el-button :loading="testing" @click="testInDialog">测试连接</el-button>
          <span style="flex: 1" />
          <el-button @click="dialog = false">取消</el-button>
          <el-button type="primary" @click="submit">{{ editing ? '保存' : '提交' }}</el-button>
        </div>
      </template>
    </el-dialog>

    <el-dialog v-model="resultVisible" title="连通性测试结果" width="460px">
      <el-alert :type="testResult.success ? 'success' : 'error'" :closable="false" :title="testResult.message" />
      <pre v-if="testResult.raw" class="mono" style="max-height: 240px; overflow: auto; background: #f5f7fa; padding: 10px">{{ testResult.raw }}</pre>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { api } from '../api'

const rows = ref([])
const plugins = ref([])
const dialog = ref(false)
const resultVisible = ref(false)
const editing = ref(null)
const advanced = ref(false)
const configText = ref('{}')
const values = reactive({})
const extra = ref({})
const testing = ref(false)
const dialogTest = reactive({ success: false, message: '' })
const testResult = reactive({ success: false, message: '', raw: '' })

const blankForm = () => ({
  device_code: '', name: '', plugin_code: 'mock', vendor: '', region: '', credential_ref: '', auto_dispatch: true,
})
const form = reactive(blankForm())

const currentPlugin = computed(() => plugins.value.find((p) => p.plugin_code === form.plugin_code) || null)
const fields = computed(() => currentPlugin.value?.manifest?.config_fields || [])

function placeholderOf(f) {
  if (f.default !== null && f.default !== undefined) return `默认 ${f.default}`
  return f.required ? '必填' : ''
}
function hintOf(f) {
  const text = String(f.description || '').replace(/^[^（(]*[（(]/, '').replace(/[）)]\s*$/, '')
  return text || f.description
}
function defaultOf(f) {
  if (f.default !== null && f.default !== undefined) return f.default
  if (f.type === 'bool') return false
  if (f.type === 'int' || f.type === 'float') return null
  return ''
}

function resetValues(pluginCode) {
  Object.keys(values).forEach((k) => delete values[k])
  extra.value = {}
  const plugin = plugins.value.find((p) => p.plugin_code === pluginCode)
  ;(plugin?.manifest?.config_fields || []).forEach((f) => { values[f.key] = defaultOf(f) })
  if (plugin?.manifest?.credential_hint && !form.credential_ref) form.credential_ref = plugin.manifest.credential_hint
}

function onPluginChange(code) {
  form.credential_ref = ''
  resetValues(code)
  advanced.value = false
  configText.value = '{}'
  dialogTest.message = ''
}

function distribute(cfg) {
  const source = cfg && typeof cfg === 'object' ? cfg : {}
  const conn = source.connection && typeof source.connection === 'object' ? source.connection : {}
  const params = source.params && typeof source.params === 'object' ? source.params : {}
  const flat = {}
  Object.keys(source).forEach((k) => {
    if (k !== 'connection' && k !== 'params') flat[k] = source[k]
  })
  const known = new Set(fields.value.map((f) => f.key))
  fields.value.forEach((f) => {
    const v = conn[f.key] ?? params[f.key] ?? flat[f.key]
    values[f.key] = v === undefined || v === null ? defaultOf(f) : v
  })
  const rest = {}
  ;[conn, params, flat].forEach((layer) => {
    Object.keys(layer).forEach((k) => { if (!known.has(k)) rest[k] = layer[k] })
  })
  extra.value = rest
}

function buildConfig() {
  const connection = {}
  const params = {}
  fields.value.forEach((f) => {
    const raw = values[f.key]
    let out
    if (f.type === 'bool') {
      out = !!raw
    } else if (f.type === 'int' || f.type === 'float') {
      out = raw === '' || raw === null || raw === undefined ? undefined : Number(raw)
      if (Number.isNaN(out)) out = undefined
    } else if (f.type === 'object') {
      const text = String(raw ?? '').trim()
      if (!text) out = undefined
      else {
        try { out = JSON.parse(text) } catch (e) { throw new Error(`${f.label} 不是合法 JSON`) }
      }
    } else {
      const text = String(raw ?? '').trim()
      out = text || undefined
    }
    if (out === undefined) return
    ;(f.group === 'connection' ? connection : params)[f.key] = out
  })
  const cfg = {}
  if (Object.keys(connection).length) cfg.connection = connection
  if (Object.keys(params).length) cfg.params = params
  return Object.assign(cfg, extra.value)
}

function currentConfig() {
  if (!advanced.value) return buildConfig()
  const text = String(configText.value || '{}').trim()
  if (!text) return {}
  const parsed = JSON.parse(text)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('配置必须是 JSON 对象')
  return parsed
}

function toggleAdvanced(on) {
  try {
    if (on) {
      configText.value = JSON.stringify(buildConfig(), null, 2)
    } else {
      const parsed = JSON.parse(String(configText.value || '{}'))
      distribute(parsed)
    }
  } catch (e) {
    ElMessage.error(`JSON 解析失败：${e.message}`)
    advanced.value = !on
  }
}

function addrOfConfig(cfg) {
  if (!cfg || typeof cfg !== 'object') return ''
  const conn = cfg.connection && typeof cfg.connection === 'object' ? cfg.connection : {}
  for (const key of ['host', 'base_url', 'endpoint']) {
    const v = conn[key] ?? cfg[key]
    if (v) return String(v)
  }
  return ''
}
function addressOf(row) {
  const addr = addrOfConfig(row.config_json)
  if (!addr) return '—'
  const port = row.config_json?.connection?.port || row.config_json?.port
  return port ? `${addr}:${port}` : addr
}

async function load() {
  rows.value = (await api.devices({ page_size: 200 })).items
  plugins.value = (await api.plugins()).items
}

function openCreate() {
  editing.value = null
  Object.assign(form, blankForm())
  dialogTest.message = ''
  resetValues(form.plugin_code)
  advanced.value = false
  configText.value = '{}'
  dialog.value = true
}

function openEdit(row) {
  editing.value = row.id
  Object.assign(form, {
    device_code: row.device_code,
    name: row.name,
    plugin_code: row.plugin_code,
    vendor: row.vendor || '',
    region: row.region || '',
    credential_ref: row.credential_ref || '',
    auto_dispatch: !!row.auto_dispatch,
  })
  dialogTest.message = ''
  resetValues(row.plugin_code)
  form.credential_ref = row.credential_ref || ''
  distribute(row.config_json)
  advanced.value = false
  dialog.value = true
}

function validateRequired() {
  const missing = fields.value.filter((f) => {
    const v = values[f.key]
    return f.required && (v === '' || v === null || v === undefined)
  })
  if (missing.length) {
    ElMessage.error(`请填写：${missing.map((f) => f.label).join('、')}`)
    return false
  }
  return true
}

async function submit() {
  if (!form.device_code || !form.name) { ElMessage.error('设备编码与名称必填'); return }
  if (!advanced.value && !validateRequired()) return
  let config_json
  try {
    config_json = currentConfig()
  } catch (e) {
    ElMessage.error(e.message)
    return
  }
  try {
    if (editing.value) {
      await api.updateDevice(editing.value, {
        name: form.name, vendor: form.vendor, region: form.region,
        config_json, credential_ref: form.credential_ref, auto_dispatch: form.auto_dispatch,
      })
      ElMessage.success('设备已保存')
    } else {
      await api.addDevice({ ...form, config_json })
      ElMessage.success('设备已创建')
    }
    dialog.value = false
    load()
  } catch (e) { /* 拦截器已提示 */ }
}

async function testInDialog() {
  if (!form.plugin_code) return
  let config_json
  try {
    config_json = { ...currentConfig(), credential_ref: form.credential_ref }
  } catch (e) {
    ElMessage.error(e.message)
    return
  }
  testing.value = true
  try {
    const res = await api.testPlugin({ plugin_code: form.plugin_code, config_json })
    dialogTest.success = !!res.success
    dialogTest.message = res.message || (res.success ? '连接正常' : '连接失败')
  } catch (e) { /* 拦截器已提示 */ } finally {
    testing.value = false
  }
}

async function test(row) {
  try {
    Object.assign(testResult, await api.testDevice(row.id))
    resultVisible.value = true
    load()
  } catch (e) { /* 拦截器已提示 */ }
}

async function remove(row) {
  try { await api.deleteDevice(row.id); ElMessage.success('已删除'); load() } catch (e) { /* 拦截器已提示 */ }
}

onMounted(load)
</script>

<style scoped>
.group-title {
  margin: 4px 0 10px;
  padding-left: 8px;
  border-left: 3px solid var(--el-color-primary);
  font-size: 13px;
  font-weight: 500;
  color: var(--el-text-color-primary);
}
.field-wrap { width: 100%; }
.field-hint {
  font-size: 12px;
  line-height: 1.5;
  color: var(--el-text-color-secondary);
  margin-top: 2px;
}
.field-hint code { padding: 0 4px; background: var(--el-fill-color-light); border-radius: 3px; }
.form-switch { margin: 0 0 12px 120px; }
.advanced-box { margin-bottom: 8px; }
.dialog-footer { display: flex; align-items: center; width: 100%; }
</style>
