<template>
  <div class="login-wrap">
    <div class="lang-switch" :title="t('common.lang.label')">
      <a :class="{ on: store.locale === 'zh-CN' }" @click="switchLang('zh-CN')">{{ t('common.lang.zh') }}</a>
      <i>/</i>
      <a :class="{ on: store.locale === 'en-US' }" @click="switchLang('en-US')">EN</a>
    </div>
    <div class="login-card">
      <h1 class="login-title">{{ t('common.app.name') }}</h1>
      <p class="login-sub">{{ t('login.sub') }}</p>
      <el-form :model="form" label-position="top" @keyup.enter="submit">
        <el-form-item :label="t('login.username')">
          <el-input v-model="form.username" placeholder="admin" :prefix-icon="User" />
        </el-form-item>
        <el-form-item :label="t('login.password')">
          <el-input v-model="form.password" type="password" show-password :placeholder="t('login.passwordPlaceholder')" :prefix-icon="Lock" />
        </el-form-item>
        <el-button class="full" type="primary" :loading="loading" @click="submit">{{ t('login.submit') }}</el-button>
      </el-form>
      <p class="text-muted" style="font-size: 11px; text-align: center; margin-top: 18px">
        {{ t('login.footer') }}
      </p>
    </div>

    <el-dialog v-model="changeVisible" :title="t('login.change.title')" width="420px" :close-on-click-modal="false" :show-close="false">
      <el-alert type="warning" :closable="false" show-icon :title="t('login.change.alertTitle')" :description="t('login.change.alertDesc')" style="margin-bottom: 16px" />
      <el-form :model="pwd" label-position="top">
        <el-form-item :label="t('login.change.old')"><el-input v-model="pwd.old_password" type="password" show-password /></el-form-item>
        <el-form-item :label="t('login.change.new')"><el-input v-model="pwd.new_password" type="password" show-password /></el-form-item>
      </el-form>
      <template #footer>
        <el-button link @click="skipChange">{{ t('login.change.later') }}</el-button>
        <el-button type="primary" :loading="changing" @click="doChange">{{ t('login.change.confirm') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { api } from '../api'
import { clearMustChange, setAuth, setLocale, setUser, store } from '../store'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const form = reactive({ username: 'admin', password: '' })
const pwd = reactive({ old_password: '', new_password: '' })
const loading = ref(false)
const changing = ref(false)
const changeVisible = ref(false)

// 登录前进不了侧边栏，所以这里单独放一个入口；否则切到英文后就再也回不去了
function switchLang(locale) {
  setLocale(locale)
}

function go() {
  router.push(route.query.redirect || '/dashboard')
}

async function submit() {
  if (!form.username || !form.password) {
    ElMessage.warning(t('login.needBoth'))
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
    ElMessage.success(t('login.pwdUpdated'))
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

<style scoped>
.login-wrap { position: relative; }
.lang-switch { position: absolute; top: 20px; right: 24px; display: flex; align-items: center; gap: 5px; font-size: 12px; }
.lang-switch a { color: #9aa3b2; cursor: pointer; }
.lang-switch a:hover { color: #3b82f6; }
.lang-switch a.on { color: #1f2a3d; font-weight: 600; }
.lang-switch i { font-style: normal; color: #c8cdd6; }
</style>
