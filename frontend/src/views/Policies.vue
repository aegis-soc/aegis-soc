<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">策略配置</h2><p class="page-desc">按优先级匹配告警，决定阈值、置信度、封禁时长与审批要求</p></div>
      <el-button type="primary" :icon="Plus" @click="openCreate">新增策略</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="priority" label="优先级" width="80" />
        <el-table-column prop="policy_code" label="编码" width="170" class-name="mono" />
        <el-table-column prop="name" label="名称" min-width="150" />
        <el-table-column prop="min_confidence" label="最低置信度" width="110" />
        <el-table-column label="阈值" width="110">
          <template #default="{ row }">{{ row.threshold_count }} 次 / {{ row.window_minutes }} 分</template>
        </el-table-column>
        <el-table-column prop="block_duration" label="封禁时长(s)" width="120" />
        <el-table-column prop="require_approval" label="审批" width="80">
          <template #default="{ row }">{{ row.require_approval ? '是' : '否' }}</template>
        </el-table-column>
        <el-table-column prop="enabled" label="启用" width="90">
          <template #default="{ row }"><el-switch :model-value="Boolean(row.enabled)" @change="toggle(row)" /></template>
        </el-table-column>
        <el-table-column label="操作" width="140" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="edit(row)">编辑</el-button>
            <el-popconfirm title="确认删除该策略？" @confirm="remove(row)">
              <template #reference><el-button link type="danger">删除</el-button></template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="dialog" :title="editing ? '编辑策略' : '新增策略'" width="560px">
      <el-form :model="form" label-width="120px">
        <el-form-item v-if="!editing" label="策略编码" required><el-input v-model="form.policy_code" /></el-form-item>
        <el-form-item label="名称" required><el-input v-model="form.name" /></el-form-item>
        <el-form-item label="优先级"><el-input-number v-model="form.priority" :min="1" /></el-form-item>
        <el-form-item label="最低置信度"><el-input-number v-model="form.min_confidence" :min="0" :max="100" /></el-form-item>
        <el-form-item label="命中阈值"><el-input-number v-model="form.threshold_count" :min="1" /> 次 / <el-input-number v-model="form.window_minutes" :min="1" /> 分钟</el-form-item>
        <el-form-item label="封禁时长(秒)"><el-input-number v-model="form.block_duration" :min="0" :step="3600" /></el-form-item>
        <el-form-item label="风险等级">
          <el-select v-model="form.risk_levels" multiple style="width: 100%">
            <el-option v-for="s in ['critical','high','medium','low']" :key="s" :label="s" :value="s" />
          </el-select>
        </el-form-item>
        <el-form-item label="需要审批"><el-switch v-model="form.require_approval" /></el-form-item>
        <el-form-item label="启用"><el-switch v-model="form.enabled" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog = false">取消</el-button><el-button type="primary" @click="submit">提交</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { api } from '../api'

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
    ElMessage.success('策略已保存')
    dialog.value = false
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
async function toggle(row) { try { await api.togglePolicy(row.id); load() } catch (e) { /* 拦截器已提示 */ } }
async function remove(row) { try { await api.deletePolicy(row.id); ElMessage.success('已删除'); load() } catch (e) { /* 拦截器已提示 */ } }
onMounted(load)
</script>
