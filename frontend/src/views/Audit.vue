<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">{{ t('audit.title') }}</h2><p class="page-desc">{{ t('audit.desc') }}</p></div>
      <el-button :icon="Refresh" @click="load">{{ t('common.action.refresh') }}</el-button>
    </div>
    <div class="filter-bar">
      <el-input v-model="query.op_type" :placeholder="t('audit.opTypePlaceholder')" clearable style="width: 240px" @keyup.enter="load" />
      <el-input v-model="query.operator" :placeholder="t('audit.operatorPlaceholder')" clearable style="width: 160px" @keyup.enter="load" />
      <el-button type="primary" @click="load">{{ t('common.action.search') }}</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="created_at" :label="t('audit.col.time')" width="170" />
        <el-table-column prop="operator" :label="t('audit.col.operator')" width="110" />
        <el-table-column prop="role_code" :label="t('audit.col.role')" width="120">
          <template #default="{ row }">{{ roleLabel(row.role_code) }}</template>
        </el-table-column>
        <el-table-column prop="op_type" :label="t('audit.col.opType')" width="200" class-name="mono" />
        <el-table-column prop="target_type" :label="t('audit.col.targetType')" width="100" />
        <el-table-column prop="target_id" :label="t('audit.col.targetId')" width="110" />
        <el-table-column prop="content" :label="t('audit.col.content')" min-width="260" show-overflow-tooltip />
        <el-table-column prop="client_ip" :label="t('audit.col.clientIp')" width="130" />
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '../api'

const { t, te } = useI18n()
const rows = ref([])
const total = ref(0)
const query = reactive({ page: 1, page_size: 20, op_type: '', operator: '' })

function roleLabel(code) {
  if (!code) return '-'
  const key = `common.role.${code}`
  return te(key) ? t(key) : code
}

async function load() {
  const params = { ...query }
  Object.keys(params).forEach((k) => { if (params[k] === '') delete params[k] })
  const data = await api.audit(params)
  rows.value = data.items
  total.value = data.total
}
onMounted(load)
</script>
