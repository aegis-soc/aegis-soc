<template>
  <div class="page">
    <div class="page-header">
      <div><h2 class="page-title">域名黑名单</h2><p class="page-desc">恶意域名 IOC，支持精确 / 子域 / 通配符匹配语义</p></div>
      <el-button type="primary" :icon="Plus" @click="dialog = true">新增域名</el-button>
    </div>
    <div class="filter-bar">
      <el-input v-model="query.keyword" placeholder="域名关键字" clearable style="width: 240px" @keyup.enter="load" />
      <el-button type="primary" @click="load">查询</el-button>
    </div>
    <div class="table-card">
      <el-table :data="rows" size="small" stripe>
        <el-table-column prop="normalized_value" label="域名" min-width="220" class-name="mono" />
        <el-table-column prop="risk_level" label="风险" width="90" />
        <el-table-column prop="status" label="状态" width="100" />
        <el-table-column prop="expire_at" label="过期时间" width="170" />
        <el-table-column prop="remark" label="备注" min-width="160" show-overflow-tooltip />
        <el-table-column label="操作" width="90" fixed="right">
          <template #default="{ row }">
            <el-popconfirm title="确认删除该域名黑名单？" @confirm="remove(row)">
              <template #reference><el-button link type="danger">删除</el-button></template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
      <div class="pager"><el-pagination background layout="total, prev, pager, next" :total="total" :page-size="query.page_size" :current-page="query.page" @current-change="(p) => { query.page = p; load() }" /></div>
    </div>

    <el-dialog v-model="dialog" title="新增域名黑名单" width="460px">
      <el-form :model="form" label-width="100px">
        <el-form-item label="域名" required><el-input v-model="form.ioc_value" placeholder="evil.example.com 或 *.example.com" /></el-form-item>
        <el-form-item label="置信度"><el-input-number v-model="form.confidence" :min="0" :max="100" /></el-form-item>
        <el-form-item label="备注"><el-input v-model="form.remark" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="立即下发"><el-switch v-model="form.dispatch" /></el-form-item>
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
const total = ref(0)
const dialog = ref(false)
const query = reactive({ page: 1, page_size: 20, keyword: '' })
const form = reactive({ ioc_value: '', confidence: 80, remark: '', dispatch: true, ioc_type: 'DOMAIN' })

async function load() {
  const params = { ...query }
  if (!params.keyword) delete params.keyword
  const data = await api.iocDomains(params)
  rows.value = data.items
  total.value = data.total
}
async function submit() {
  try {
    await api.addIocDomain(form)
    ElMessage.success('域名已加入黑名单')
    dialog.value = false
    form.ioc_value = ''
    load()
  } catch (e) { /* 拦截器已提示 */ }
}
async function remove(row) {
  try { await api.deleteIocDomain(row.id); ElMessage.success('已删除'); load() } catch (e) { /* 拦截器已提示 */ }
}
onMounted(load)
</script>
