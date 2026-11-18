<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">{{ t('policies.title') }}</h2><p class="page-desc">{{ t('policies.desc') }}</p></div>
      <el-button type="primary" :icon="Plus" @click="openCreate">{{ t('policies.add') }}</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="priority" :label="t('policies.col.priority')" width="80" />
        <el-table-column prop="policy_code" :label="t('policies.col.code')" width="170" class-name="mono" />
        <el-table-column prop="name" :label="t('policies.col.name')" min-width="150" />
        <el-table-column prop="min_confidence" :label="t('policies.col.minConfidence')" width="120" />
        <el-table-column :label="t('policies.col.threshold')" width="150">
          <template #default="{ row }">{{ t('policies.thresholdValue', { count: row.threshold_count, minutes: row.window_minutes }) }}</template>
        </el-table-column>
        <el-table-column prop="block_duration" :label="t('policies.col.blockDuration')" width="130" />
        <el-table-column prop="require_approval" :label="t('policies.col.approval')" width="90">
          <template #default="{ row }">{{ row.require_approval ? t('common.label.yes') : t('common.label.no') }}</template>
        </el-table-column>
        <el-table-column prop="enabled" :label="t('policies.col.enabled')" width="90">
          <template #default="{ row }"><el-switch :model-value="Boolean(row.enabled)" @change="toggle(row)" /></template>
        </el-table-column>
        <el-table-column :label="t('policies.col.actions')" width="150" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="edit(row)">{{ t('common.action.edit') }}</el-button>
            <el-popconfirm :title="t('policies.confirmDelete')" @confirm="remove(row)">
              <template #reference><el-button link type="danger">{{ t('common.action.delete') }}</el-button></template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="dialog" :title="editing ? t('policies.dialog.edit') : t('policies.dialog.create')" width="560px">
      <el-form :model="form" label-width="130px">
        <el-form-item v-if="!editing" :label="t('policies.form.code')" required><el-input v-model="form.policy_code" /></el-form-item>
        <el-form-item :label="t('policies.form.name')" required><el-input v-model="form.name" /></el-form-item>
        <el-form-item :label="t('policies.form.priority')"><el-input-number v-model="form.priority" :min="1" /></el-form-item>
        <el-form-item :label="t('policies.form.minConfidence')"><el-input-number v-model="form.min_confidence" :min="0" :max="100" /></el-form-item>
        <el-form-item :label="t('policies.form.threshold')">
          <el-input-number v-model="form.threshold_count" :min="1" />
          <span class="unit">{{ t('policies.form.unitHits') }} /</span>
          <el-input-number v-model="form.window_minutes" :min="1" />
          <span class="unit">{{ t('policies.form.unitMinutes') }}</span>
        </el-form-item>
        <el-form-item :label="t('policies.form.blockDuration')"><el-input-number v-model="form.block_duration" :min="0" :step="3600" /></el-form-item>
        <el-form-item :label="t('policies.form.riskLevels')">
          <el-select v-model="form.risk_levels" multiple style="width: 100%">
            <el-option v-for="s in ['critical','high','medium','low']" :key="s" :label="riskLabel(s)" :value="s" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('policies.form.approval')"><el-switch v-model="form.require_approval" /></el-form-item>
        <el-form-item :label="t('policies.form.enabled')"><el-switch v-model="form.enabled" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog = false">{{ t('common.action.cancel') }}</el-button><el-button type="primary" @click="submit">{{ t('policies.form.submit') }}</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { api } from '../api'

const { t, te } = useI18n()
const rows = ref([])
const dialog = ref(false)
const editing = ref(false)
const editId = ref(null)
const form = reactive({
  policy_code: '', name: '', priority: 100, min_confidence: 60,
  threshold_count: 1, window_minutes: 10, block_duration: 7200,
  risk_levels: ['critical', 'high', 'medium'], require_approval: false,
  auto_dispatch: true, enabled: true, conditions: {}, target_plugins: [],
})

function riskLabel(level) {
  const key = `enums.risk.${level}`
  return te(key) ? t(key) : level
}

async function load() { rows.value = (await api.policies({ page_size: 200 })).items }
function openCreate() {
  editing.value = false
  Object.assign(form, { policy_code: '', name: '', priority: 100, min_confidence: 60, threshold_count: 1, window_minutes: 10, block_duration: 7200, risk_levels: ['critical', 'high', 'medium'], require_approval: false, enabled: true })
  dialog.value = true
}
function edit(row) {
  editing.value = true
  editId.value = row.id
  Object.assign(form, { ...row, risk_levels: row.risk_levels || [], enabled: Boolean(row.enabled), require_approval: Boolean(row.require_approval) })
  dialog.value = true
}
async function submit() {
  try {
    if (editing.value) await api.updatePolicy(editId.value, form)
    else await api.addPolicy(form)
    ElMessage.success(t('policies.saved'))
    dialog.value = false
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
async function toggle(row) { try { await api.togglePolicy(row.id); load() } catch (e) { /* 拦截器已提示 */ } }
async function remove(row) { try { await api.deletePolicy(row.id); ElMessage.success(t('policies.deleted')); load() } catch (e) { /* 拦截器已提示 */ } }
onMounted(load)
</script>

<style scoped>
.unit { margin: 0 6px; font-size: 12px; color: #909399; }
</style>
