<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">{{ t('plugins.title') }}</h2><p class="page-desc">{{ t('plugins.desc') }}</p></div>
      <el-button :icon="Refresh" @click="load">{{ t('common.action.refresh') }}</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="plugin_code" :label="t('plugins.col.code')" width="160" class-name="mono" />
        <el-table-column prop="plugin_name" :label="t('plugins.col.name')" min-width="170" />
        <el-table-column prop="version" :label="t('plugins.col.version')" width="90" />
        <el-table-column :label="t('plugins.col.iocTypes')" width="150">
          <template #default="{ row }"><el-tag v-for="code in (row.manifest?.ioc_types || [])" :key="code" size="small" style="margin: 2px">{{ code }}</el-tag></template>
        </el-table-column>
        <el-table-column :label="t('plugins.col.capabilities')" width="200">
          <template #default="{ row }"><el-tag v-for="cap in (row.manifest?.capabilities || [])" :key="cap" size="small" type="info" style="margin: 2px">{{ cap }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="description" :label="t('plugins.col.desc')" min-width="220" show-overflow-tooltip />
        <el-table-column :label="t('plugins.col.actions')" width="100" fixed="right">
          <template #default="{ row }"><el-button link type="primary" @click="openTest(row)">{{ t('common.action.test') }}</el-button></template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="testVisible" :title="t('plugins.test.title', { code: current?.plugin_code })" width="500px">
      <p class="text-muted" style="font-size: 12px">{{ t('plugins.test.hint') }}</p>
      <el-input v-model="configText" type="textarea" :rows="5" placeholder='{"mode":"log"}' />
      <template #footer><el-button @click="testVisible = false">{{ t('common.action.cancel') }}</el-button><el-button type="primary" @click="doTest">{{ t('plugins.test.run') }}</el-button></template>
      <el-alert v-if="testResult" :type="testResult.success ? 'success' : 'error'" :closable="false" :title="testResult.message" style="margin-top: 14px" />
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '../api'

const { t } = useI18n()
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
  try { config = JSON.parse(configText.value || '{}') } catch (e) { ElMessage.error(t('plugins.test.invalidJson')); return }
  try {
    testResult.value = await api.testPlugin({ plugin_code: current.value.plugin_code, config_json: config })
  } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
