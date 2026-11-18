<template>
  <el-config-provider :locale="elLocale">
    <router-view />
  </el-config-provider>
</template>

<script setup>
import { computed } from 'vue'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import en from 'element-plus/es/locale/lang/en'
import { store } from './store'

// Element Plus 自带的文案（分页「共 N 条」、日期面板、空状态）只认这里，
// 不接这一层，英文界面里会混出一半中文。
const elLocale = computed(() => (store.locale === 'en-US' ? en : zhCn))
</script>
