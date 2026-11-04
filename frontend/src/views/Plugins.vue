<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">插件管理</h2><p class="page-desc">统一设备网关，插件通过 Manifest 声明支持的 IOC 类型与能力</p></div>
      <el-button :icon="Refresh" @click="load">刷新</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="plugin_code" label="插件编码" width="160" class-name="mono" />
        <el-table-column prop="plugin_name" label="名称" min-width="170" />
        <el-table-column prop="version" label="版本" width="90" />
        <el-table-column label="IOC 类型" width="150">
          <template #default="{ row }"><el-tag v-for="t in (row.manifest?.ioc_types || [])" :key="t" size="small" style="margin: 2px">{{ t }}</el-tag></template>
        </el-table-column>
        <el-table-column label="能力" width="200">
          <template #default="{ row }"><el-tag v-for="c in (row.manifest?.capabilities || [])" :key="c" size="small" type="info" style="margin: 2px">{{ c }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="description" label="说明" min-width="220" show-overflow-tooltip />
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }"><el-button link type="primary" @click="openTest(row)">测试</el-button></template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="testVisible" :title="`测试插件：${current?.plugin_code}`" width="500px">
      <p class="text-muted" style="font-size: 12px">连通性测试不会产生任何封禁动作。真实设备的凭据请通过设备的 credential_ref 注入。</p>
      <el-input v-model="configText" type="textarea" :rows="5" placeholder='{"mode":"log"}' />
      <template #footer><el-button @click="testVisible = false">取消</el-button><el-button type="primary" @click="doTest">执行测试</el-button></template>
      <el-alert v-if="testResult" :type="testResult.success ? 'success' : 'error'" :closable="false" :title="testResult.message" style="margin-top: 14px" />
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '../api'

const rows = ref([])
const testVisible = ref(false)
const current = ref(null)
const configText = ref('{}')
const testResult = ref(null)

async function load() { rows.value = (await api.plugins()).items }
function openTest(row) {
  current.value = row
  configText.value = JSON.stringify(row.manifest?.config_schema || {}, null, 2)
  testResult.value = null
  testVisible.value = true
}
async function doTest() {
  let config = {}
  try { config = JSON.parse(configText.value || '{}') } catch (e) { ElMessage.error('配置不是合法 JSON'); return }
  try {
    testResult.value = await api.testPlugin({ plugin_code: current.value.plugin_code, config_json: config })
  } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
