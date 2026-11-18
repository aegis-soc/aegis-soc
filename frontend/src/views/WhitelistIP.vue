<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">{{ t('whitelist.title') }}</h2><p class="page-desc">{{ t('whitelist.desc') }}</p></div>
      <div>
        <el-button :icon="Upload" @click="importVisible = true">{{ t('whitelist.import') }}</el-button>
        <el-button type="primary" :icon="Plus" @click="dialog = true">{{ t('whitelist.add') }}</el-button>
      </div>
    </div>
    <div class="filter-bar">
      <el-input v-model="checkIp" :placeholder="t('whitelist.checkPlaceholder')" style="width: 280px" />
      <el-button @click="doCheck">{{ t('whitelist.check') }}</el-button>
      <el-tag v-if="checkResult" :type="checkResult.whitelisted ? 'warning' : 'success'" effect="light">
        {{ checkResult.whitelisted ? t('whitelist.protected', { matched: checkResult.matched }) : t('whitelist.notMatched') }}
      </el-tag>
      <el-input v-model="query.keyword" :placeholder="t('whitelist.keywordPlaceholder')" clearable style="width: 200px" @keyup.enter="load" />
      <el-button type="primary" @click="load">{{ t('common.action.search') }}</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="cidr" :label="t('whitelist.col.cidr')" min-width="180" class-name="mono">
          <template #default="{ row }">{{ row.cidr || row.ip_value }}</template>
        </el-table-column>
        <el-table-column prop="prefix_len" :label="t('whitelist.col.mask')" width="90" />
        <el-table-column prop="cidr_flag" :label="t('whitelist.col.type')" width="110">
          <template #default="{ row }">{{ row.cidr_flag ? t('whitelist.type.cidr') : t('whitelist.type.single') }}</template>
        </el-table-column>
        <el-table-column prop="remark" :label="t('whitelist.col.remark')" min-width="200" show-overflow-tooltip />
        <el-table-column prop="created_by" :label="t('whitelist.col.createdBy')" width="110" />
        <el-table-column :label="t('whitelist.col.actions')" width="90" fixed="right">
          <template #default="{ row }">
            <el-popconfirm :title="t('whitelist.confirmDelete')" @confirm="remove(row)">
              <template #reference><el-button link type="danger">{{ t('common.action.delete') }}</el-button></template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>

    <el-dialog v-model="dialog" :title="t('whitelist.dialog.title')" width="460px">
      <el-form :model="form" label-width="130px">
        <el-form-item :label="t('whitelist.dialog.ip')" required><el-input v-model="form.ip_value" :placeholder="t('whitelist.dialog.ipPlaceholder')" /></el-form-item>
        <el-form-item :label="t('common.label.remark')"><el-input v-model="form.remark" type="textarea" :rows="2" /></el-form-item>
        <el-form-item :label="t('whitelist.dialog.unblockExisting')"><el-switch v-model="form.unblock_existing" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog = false">{{ t('common.action.cancel') }}</el-button><el-button type="primary" @click="submit">{{ t('common.action.submit') }}</el-button></template>
    </el-dialog>

    <el-dialog v-model="importVisible" :title="t('whitelist.importDialog.title')" width="520px">
      <p class="text-muted" style="font-size: 12px">{{ t('whitelist.importDialog.hint') }}</p>
      <el-input v-model="importText" type="textarea" :rows="8" :placeholder="t('whitelist.importDialog.placeholder')" />
      <template #footer><el-button @click="importVisible = false">{{ t('common.action.cancel') }}</el-button><el-button type="primary" @click="doImport">{{ t('common.action.import') }}</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Plus, Upload } from '@element-plus/icons-vue'
import { api } from '../api'

const { t } = useI18n()
const rows = ref([])
const total = ref(0)
const dialog = ref(false)
const importVisible = ref(false)
const importText = ref('')
const checkIp = ref('')
const checkResult = ref(null)
const query = reactive({ page: 1, page_size: 20, keyword: '' })
const form = reactive({ ip_value: '', remark: '', unblock_existing: true })

async function load() {
  const params = { ...query }
  if (!params.keyword) delete params.keyword
  const data = await api.whitelist(params)
  rows.value = data.items
  total.value = data.total
}
async function doCheck() {
  if (!checkIp.value) return
  try { checkResult.value = await api.checkWhitelist(checkIp.value) } catch (e) { /* 拦截器已提示 */ }
}
async function submit() {
  try {
    const data = await api.addWhitelist(form)
    ElMessage.success(t('whitelist.saved', { n: data.unblock_task_count }))
    dialog.value = false
    form.ip_value = ''
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
async function doImport() {
  try {
    const data = await api.importWhitelist(importText.value)
    ElMessage.success(t('whitelist.imported', { created: data.created, skipped: data.skipped, errors: data.errors.length }))
    importVisible.value = false
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
async function remove(row) {
  try { await api.deleteWhitelist(row.id); ElMessage.success(t('whitelist.deleted')); load() } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
