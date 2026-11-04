<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">设备管理</h2><p class="page-desc">安全设备资产与插件配置，凭据仅通过环境变量引用</p></div>
      <el-button type="primary" :icon="Plus" @click="openCreate">新增设备</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="device_code" label="设备编码" width="160" class-name="mono" />
        <el-table-column prop="name" label="名称" min-width="150" />
        <el-table-column prop="vendor" label="厂商" width="120" />
        <el-table-column prop="plugin_code" label="插件" width="140" />
        <el-table-column prop="region" label="区域" width="100" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }"><el-tag size="small" :type="row.status === 'online' ? 'success' : 'info'">{{ row.status }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="auto_dispatch" label="自动下发" width="90">
          <template #default="{ row }">{{ row.auto_dispatch ? '是' : '否' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="170" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="test(row)">连通性测试</el-button>
            <el-popconfirm title="确认删除该设备？" @confirm="remove(row)">
              <template #reference><el-button link type="danger">删除</el-button></template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="dialog" title="新增设备" width="540px">
      <el-form :model="form" label-width="120px">
        <el-form-item label="设备编码" required><el-input v-model="form.device_code" placeholder="如 fw-hq-01" /></el-form-item>
        <el-form-item label="名称" required><el-input v-model="form.name" /></el-form-item>
        <el-form-item label="插件" required>
          <el-select v-model="form.plugin_code" style="width: 100%">
            <el-option v-for="p in plugins" :key="p.plugin_code" :label="`${p.plugin_name} (${p.plugin_code})`" :value="p.plugin_code" />
          </el-select>
        </el-form-item>
        <el-form-item label="厂商"><el-input v-model="form.vendor" /></el-form-item>
        <el-form-item label="区域"><el-input v-model="form.region" /></el-form-item>
        <el-form-item label="插件配置(JSON)"><el-input v-model="configText" type="textarea" :rows="4" placeholder='{"mode":"log"}' /></el-form-item>
        <el-form-item label="凭据环境变量"><el-input v-model="form.credential_ref" placeholder="如 FW_HQ_PASSWORD（值为口令或含 password 的 JSON）" /></el-form-item>
        <el-form-item label="允许自动下发"><el-switch v-model="form.auto_dispatch" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog = false">取消</el-button><el-button type="primary" @click="submit">提交</el-button></template>
    </el-dialog>

    <el-dialog v-model="resultVisible" title="连通性测试结果" width="460px">
      <el-alert :type="testResult.success ? 'success' : 'error'" :closable="false" :title="testResult.message" />
      <pre v-if="testResult.raw" class="mono" style="max-height: 240px; overflow: auto; background: #f5f7fa; padding: 10px">{{ testResult.raw }}</pre>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { api } from '../api'

const rows = ref([])
const plugins = ref([])
const dialog = ref(false)
const resultVisible = ref(false)
const configText = ref('{}')
const testResult = reactive({ success: false, message: '', raw: '' })
const form = reactive({ device_code: '', name: '', plugin_code: 'mock', vendor: '', region: '', credential_ref: '', auto_dispatch: true })

async function load() {
  rows.value = (await api.devices({ page_size: 200 })).items
  plugins.value = (await api.plugins()).items
}
function openCreate() { dialog.value = true }
async function submit() {
  let config_json = {}
  try { config_json = JSON.parse(configText.value || '{}') } catch (e) { ElMessage.error('插件配置不是合法 JSON'); return }
  try {
    await api.addDevice({ ...form, config_json })
    ElMessage.success('设备已创建')
    dialog.value = false
    load()
  } catch (e) { /* 拦截器已提示 */ }
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
