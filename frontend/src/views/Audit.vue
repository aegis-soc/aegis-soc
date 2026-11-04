<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">操作审计</h2><p class="page-desc">人工操作、自动封禁、白名单豁免与系统变更全链路留痕</p></div>
      <el-button :icon="Refresh" @click="load">刷新</el-button>
    </div>
    <div class="filter-bar">
      <el-input v-model="query.op_type" placeholder="操作类型，如 WHITELIST_HIT" clearable style="width: 240px" @keyup.enter="load" />
      <el-input v-model="query.operator" placeholder="操作人" clearable style="width: 160px" @keyup.enter="load" />
      <el-button type="primary" @click="load">查询</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="created_at" label="时间" width="170" />
        <el-table-column prop="operator" label="操作人" width="110" />
        <el-table-column prop="role_code" label="角色" width="110" />
        <el-table-column prop="op_type" label="操作类型" width="200" class-name="mono" />
        <el-table-column prop="target_type" label="对象类型" width="100" />
        <el-table-column prop="target_id" label="对象 ID" width="110" />
        <el-table-column prop="content" label="内容" min-width="260" show-overflow-tooltip />
        <el-table-column prop="client_ip" label="来源 IP" width="130" />
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '../api'

const rows = ref([])
const total = ref(0)
const query = reactive({ page: 1, page_size: 20, op_type: '', operator: '' })

async function load() {
  const params = { ...query }
  Object.keys(params).forEach((k) => { if (params[k] === '') delete params[k] })
  const data = await api.audit(params)
  rows.value = data.items
  total.value = data.total
}
onMounted(load)
</script>
