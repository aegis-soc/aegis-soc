<template>
  <div class="login-wrap">
    <div class="login-card">
      <h1 class="login-title">宙斯盾 Aegis</h1>
      <p class="login-sub">通用安全运营自动化 AI+SOC 平台 · 请登录</p>
      <el-form :model="form" label-position="top" @keyup.enter="submit">
        <el-form-item label="用户名">
          <el-input v-model="form.username" placeholder="admin" :prefix-icon="User" />
        </el-form-item>
        <el-form-item label="口令">
          <el-input v-model="form.password" type="password" show-password placeholder="请输入口令" :prefix-icon="Lock" />
        </el-form-item>
        <el-button class="full" type="primary" :loading="loading" @click="submit">登 录</el-button>
      </el-form>
      <p class="text-muted" style="font-size: 11px; text-align: center; margin-top: 18px">
        默认账号首次登录需修改口令 · Apache 2.0
      </p>
    </div>

    <el-dialog v-model="changeVisible" title="修改默认口令" width="420px" :close-on-click-modal="false" :show-close="false">
      <el-alert type="warning" :closable="false" show-icon title="安全提示" description="检测到初始口令，请修改后再使用平台。" style="margin-bottom: 16px" />
      <el-form :model="pwd" label-position="top">
        <el-form-item label="原口令"><el-input v-model="pwd.old_password" type="password" show-password /></el-form-item>
        <el-form-item label="新口令"><el-input v-model="pwd.new_password" type="password" show-password /></el-form-item>
      </el-form>
      <template #footer>
        <el-button link @click="skipChange">稍后修改</el-button>
        <el-button type="primary" :loading="changing" @click="doChange">确认修改</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { api } from '../api'
import { clearMustChange, setAuth, setUser } from '../store'

const route = useRoute()
const router = useRouter()
const form = reactive({ username: 'admin', password: '' })
const pwd = reactive({ old_password: '', new_password: '' })
const loading = ref(false)
const changing = ref(false)
const changeVisible = ref(false)

function go() {
  router.push(route.query.redirect || '/dashboard')
}

async function submit() {
  if (!form.username || !form.password) {
    ElMessage.warning('请输入用户名和口令')
    return
  }
  loading.value = true
  try {
    const data = await api.login({ username: form.username, password: form.password })
    setAuth(data)
    setUser(form.username)
    if (data.must_change_password) {
      pwd.old_password = form.password
      changeVisible.value = true
    } else {
      go()
    }
  } catch (e) { /* 拦截器已提示 */ } finally {
    loading.value = false
  }
}

async function doChange() {
  changing.value = true
  try {
    await api.changePassword({ old_password: pwd.old_password, new_password: pwd.new_password })
    clearMustChange()
    changeVisible.value = false
    ElMessage.success('口令已更新')
    go()
  } catch (e) { /* 拦截器已提示 */ } finally {
    changing.value = false
  }
}

function skipChange() {
  changeVisible.value = false
  go()
}
</script>
