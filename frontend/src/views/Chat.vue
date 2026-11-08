<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h2 class="page-title">人机对话</h2>
        <p class="page-desc">
          用中文提问，系统自动判断是查平台数据（黑名单 / 告警 / 下发 / 设备）还是查 Graylog 三流日志，
          给出结论 + 明细 + 编译后的查询。只读、可审计，不会改动任何数据。
        </p>
      </div>
      <div style="display: flex; gap: 8px">
        <el-button :icon="Refresh" :loading="loadingSessions" @click="loadSessions">刷新会话</el-button>
        <el-button type="primary" :icon="Plus" @click="newSession">新对话</el-button>
      </div>
    </div>

    <div class="chat-wrap">
      <aside class="chat-aside">
        <div class="aside-title">我的会话</div>
        <div v-if="!sessions.length" class="aside-empty">还没有会话，右侧直接提问即可</div>
        <div
          v-for="item in sessions" :key="item.id"
          class="session-item" :class="{ active: item.id === sessionId }"
          @click="openSession(item.id)"
        >
          <div class="session-title">{{ item.title }}</div>
          <div class="session-meta">
            <span>{{ item.message_count }} 条</span>
            <span>{{ fmtTime(item.updated_at) }}</span>
            <el-icon class="session-del" @click.stop="removeSession(item.id)"><Delete /></el-icon>
          </div>
        </div>
      </aside>

      <section class="chat-main">
        <div ref="scroller" class="chat-body">
          <div v-if="!messages.length" class="empty">
            <div class="empty-title">问点什么？</div>
            <div class="empty-sub">规则解析，不依赖大模型；问法里的时间、topN、维度都能识别。</div>
            <div class="chips">
              <div v-for="tip in suggestions" :key="tip" class="chip" @click="fill(tip)">{{ tip }}</div>
            </div>
            <div v-if="catalog.length" class="catalog">
              <div v-for="src in catalog" :key="src.key" class="catalog-item">
                <span class="catalog-name">{{ src.label }}</span>
                <span class="catalog-dims">可看：{{ src.dims.map((d) => d.label).join('、') }}</span>
              </div>
            </div>
          </div>

          <div v-for="(msg, index) in messages" :key="index" class="msg" :class="msg.role">
            <div class="bubble">
              <div v-if="msg.role === 'user'" class="q">{{ msg.content }}</div>
              <template v-else>
                <div class="a">{{ msg.content }}</div>

                <div v-for="(block, bi) in msg.blocks || []" :key="bi" class="block">
                  <div v-if="block.type === 'kpi'" class="kpi-row">
                    <div v-for="kpi in block.items" :key="kpi.label" class="kpi">
                      <div class="kpi-label">{{ kpi.label }}</div>
                      <div class="kpi-value">{{ fmtNum(kpi.value) }}</div>
                    </div>
                  </div>

                  <div v-else-if="block.type === 'table'" class="tbl">
                    <div class="block-title">{{ block.title }}</div>
                    <table>
                      <thead>
                        <tr><th v-for="col in block.columns" :key="col.key">{{ col.label }}</th></tr>
                      </thead>
                      <tbody>
                        <tr v-for="(row, ri) in block.rows" :key="ri">
                          <td v-for="col in block.columns" :key="col.key">
                            <el-tag v-if="col.key === 'blocked' && row.internal" size="small" type="info">内网</el-tag>
                            <el-tag v-else-if="col.key === 'blocked'" size="small" :type="row.blocked ? 'success' : 'warning'">
                              {{ row.blocked ? '已封' : '未封' }}
                            </el-tag>
                            <span v-else-if="col.key === 'value'">{{ fmtNum(row.value) }}</span>
                            <span v-else-if="col.key === 'label'" class="cell-key">{{ row.label }}</span>
                            <span v-else>{{ row[col.key] || '—' }}</span>
                          </td>
                        </tr>
                      </tbody>
                    </table>
                    <div v-if="block.truncated" class="block-hint">按前 {{ block.rows.length }} 条展示，不是全量</div>
                  </div>

                  <div v-else-if="block.type === 'bar'" class="bars">
                    <div class="block-title">{{ block.title }}</div>
                    <div v-for="(cat, ci) in block.categories" :key="ci" class="bar-row">
                      <span class="bar-label">{{ cat }}</span>
                      <span class="bar-track">
                        <span class="bar-fill" :style="{ width: barWidth(block.values, ci) }" />
                      </span>
                      <span class="bar-value">{{ fmtNum(block.values[ci]) }}</span>
                    </div>
                  </div>

                  <div v-else-if="block.type === 'note'" class="note">
                    <div class="block-title">{{ block.title }}</div>
                    <div v-for="(line, li) in block.lines" :key="li" class="note-line">· {{ line }}</div>
                  </div>
                </div>

                <div v-if="msg.suggestions && msg.suggestions.length" class="chips chips-inline">
                  <div v-for="tip in msg.suggestions" :key="tip" class="chip" @click="fill(tip)">{{ tip }}</div>
                </div>

                <el-collapse v-if="msg.trace" class="trace">
                  <el-collapse-item title="查看查询详情（怎么理解这句话的）" :name="index">
                    <div class="trace-row">
                      <span>路由：{{ msg.trace.route }}</span>
                      <span v-if="msg.trace.confidence !== undefined">置信度：{{ msg.trace.confidence }}</span>
                      <span v-if="msg.trace.elapsed_ms !== undefined">耗时：{{ msg.trace.elapsed_ms }} ms</span>
                      <span v-if="msg.trace.matched && msg.trace.matched.length">命中：{{ msg.trace.matched.join('、') }}</span>
                    </div>
                    <div v-for="(query, qi) in msg.trace.queries || []" :key="qi" class="trace-query">
                      <div class="trace-sub">
                        <span>数据源 {{ query.source || '三流日志' }}</span>
                        <span v-if="query.group_by">按 {{ query.group_by }}</span>
                        <span v-if="query.query_desc">{{ query.query_desc }}</span>
                        <span v-if="query.window">{{ query.window.start }} → {{ query.window.end }}</span>
                        <span v-if="query.fetched !== null && query.fetched !== undefined">扫描 {{ query.fetched }} 条 / 命中 {{ query.matched }}</span>
                      </div>
                      <pre v-if="query.sql" class="sql">{{ query.sql }}</pre>
                      <div v-if="query.stream_stats && query.stream_stats.length" class="trace-sub">
                        <span v-for="st in query.stream_stats" :key="st.name">
                          {{ st.name }}: {{ st.fetched ?? 0 }} 条{{ st.error ? '（失败）' : '' }}
                        </span>
                      </div>
                    </div>
                    <div class="trace-foot">
                      <el-button size="small" :icon="CopyDocument" @click="copy(msg.content)">复制结论</el-button>
                    </div>
                  </el-collapse-item>
                </el-collapse>
              </template>
            </div>
          </div>

          <div v-if="asking" class="msg assistant">
            <div class="bubble thinking">
              <span class="dot" /><span class="dot" /><span class="dot" />
              <span class="thinking-text">正在解析意图并查询…</span>
            </div>
          </div>
        </div>

        <div class="chat-input">
          <el-input
            v-model="question" type="textarea" :rows="2" resize="none" maxlength="300" show-word-limit
            placeholder="例如：分析黑名单中来源 top10 和 top 国家 / 最近 3 天各设备有未拦截的 IP 日志"
            @keydown.enter.exact.prevent="submit"
          />
          <div class="input-actions">
            <span class="input-hint">Enter 发送 · Shift+Enter 换行 · 只读查询，每分钟最多 20 次</span>
            <el-button type="primary" :icon="Promotion" :loading="asking" :disabled="!question.trim()" @click="submit">
              发送
            </el-button>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CopyDocument, Delete, Plus, Promotion, Refresh } from '@element-plus/icons-vue'
import { api } from '../api'

const sessions = ref([])
const sessionId = ref(null)
const messages = ref([])
const question = ref('')
const asking = ref(false)
const loadingSessions = ref(false)
const suggestions = ref([])
const catalog = ref([])
const scroller = ref(null)

async function loadCatalog() {
  try {
    const data = await api.chatCatalog()
    suggestions.value = data.suggestions || []
    catalog.value = data.sources || []
  } catch (e) { /* 拦截器已提示 */ }
}

async function loadSessions() {
  loadingSessions.value = true
  try {
    sessions.value = await api.chatSessions()
  } catch (e) { /* 拦截器已提示 */ } finally {
    loadingSessions.value = false
  }
}

function newSession() {
  sessionId.value = null
  messages.value = []
  question.value = ''
}

async function openSession(id) {
  if (id === sessionId.value) return
  try {
    const data = await api.chatSession(id)
    sessionId.value = id
    messages.value = (data.messages || []).map((row) => ({
      role: row.role,
      content: row.content,
      blocks: row.blocks || [],
      trace: row.trace,
      suggestions: [],
    }))
    scrollBottom()
  } catch (e) { /* 拦截器已提示 */ }
}

async function removeSession(id) {
  try {
    await ElMessageBox.confirm('删除后这段对话记录不可恢复，确定删除？', '删除会话', { type: 'warning' })
  } catch (e) { return }
  try {
    await api.chatDeleteSession(id)
    sessions.value = sessions.value.filter((item) => item.id !== id)
    if (sessionId.value === id) newSession()
  } catch (e) { /* 拦截器已提示 */ }
}

function fill(text) {
  question.value = text
}

async function submit() {
  const text = question.value.trim()
  if (!text || asking.value) return
  messages.value.push({ role: 'user', content: text, blocks: [], trace: null })
  question.value = ''
  asking.value = true
  scrollBottom()
  try {
    const data = await api.chatAsk({ question: text, session_id: sessionId.value })
    sessionId.value = data.session_id
    messages.value.push({
      role: 'assistant',
      content: data.answer,
      blocks: data.blocks || [],
      trace: data.trace,
      suggestions: data.suggestions || [],
    })
    loadSessions()
  } catch (e) {
    messages.value.push({
      role: 'assistant',
      content: '这次没查成，可以换个问法再试一次。',
      blocks: [],
      trace: null,
      suggestions: [],
    })
  } finally {
    asking.value = false
    scrollBottom()
  }
}

function scrollBottom() {
  nextTick(() => {
    if (scroller.value) scroller.value.scrollTop = scroller.value.scrollHeight
  })
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制')
  } catch (e) {
    ElMessage.warning('浏览器不允许复制，请手动选择文本')
  }
}

function fmtNum(value) {
  const number = Number(value || 0)
  if (Number.isInteger(number)) return number.toLocaleString('zh-CN')
  return number.toLocaleString('zh-CN', { maximumFractionDigits: 1 })
}

function fmtTime(value) {
  if (!value) return ''
  const date = new Date(value.endsWith('Z') ? value : `${value}Z`)
  if (Number.isNaN(date.getTime())) return value
  const pad = (n) => String(n).padStart(2, '0')
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

const maxOf = (values) => Math.max(...values.map((v) => Number(v) || 0), 1)
function barWidth(values, index) {
  const max = maxOf(values)
  return `${Math.max(2, (Number(values[index]) / max) * 100)}%`
}

onMounted(async () => {
  await Promise.all([loadCatalog(), loadSessions()])
})
</script>

<style scoped>
.chat-wrap { display: flex; gap: 16px; height: calc(100vh - 210px); min-height: 480px; }
.chat-aside { width: 210px; flex: none; background: #fff; border: 1px solid #ebeef5; border-radius: 8px; padding: 12px; overflow: auto; }
.aside-title { font-size: 12px; color: #909399; margin-bottom: 8px; }
.aside-empty { font-size: 12px; color: #c0c4cc; line-height: 1.6; }
.session-item { padding: 8px 10px; border-radius: 6px; cursor: pointer; margin-bottom: 4px; }
.session-item:hover { background: var(--el-fill-color-light); }
.session-item.active { background: var(--el-color-primary-light-9); }
.session-title { font-size: 13px; color: var(--el-text-color-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.session-meta { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #a8abb2; margin-top: 2px; }
.session-del { margin-left: auto; opacity: 0; }
.session-item:hover .session-del { opacity: 1; color: var(--el-color-danger); }
.chat-main { flex: 1; display: flex; flex-direction: column; background: #fff; border: 1px solid #ebeef5; border-radius: 8px; overflow: hidden; }
.chat-body { flex: 1; overflow: auto; padding: 18px; }
.empty { padding: 24px 8px; }
.empty-title { font-size: 16px; font-weight: 600; color: var(--el-text-color-primary); }
.empty-sub { font-size: 12px; color: #909399; margin: 6px 0 14px; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; }
.chips-inline { margin-top: 10px; }
.chip { font-size: 12px; padding: 5px 10px; border-radius: 14px; background: var(--el-color-primary-light-9); color: var(--el-color-primary); cursor: pointer; }
.chip:hover { background: var(--el-color-primary-light-8); }
.catalog { margin-top: 20px; border-top: 1px dashed #ebeef5; padding-top: 12px; }
.catalog-item { font-size: 12px; color: #909399; line-height: 1.9; }
.catalog-name { color: var(--el-text-color-primary); font-weight: 600; margin-right: 8px; }
.msg { display: flex; margin-bottom: 14px; }
.msg.user { justify-content: flex-end; }
.bubble { max-width: 86%; border-radius: 10px; padding: 12px 14px; font-size: 13px; line-height: 1.7; }
.msg.user .bubble { background: var(--el-color-primary); color: #fff; max-width: 70%; }
.msg.assistant .bubble { background: #f7f8fa; color: var(--el-text-color-primary); }
.q { white-space: pre-wrap; }
.a { white-space: pre-wrap; }
.thinking { display: flex; align-items: center; gap: 4px; }
.thinking-text { font-size: 12px; color: #909399; margin-left: 6px; }
.dot { width: 5px; height: 5px; border-radius: 50%; background: var(--el-color-primary); animation: blink 1.2s infinite; }
.dot:nth-child(2) { animation-delay: 0.2s; }
.dot:nth-child(3) { animation-delay: 0.4s; }
@keyframes blink { 0%, 100% { opacity: 0.25; } 50% { opacity: 1; } }
.block { margin-top: 12px; }
.block-title { font-size: 12px; color: #909399; margin-bottom: 6px; }
.block-hint { font-size: 11px; color: #c0c4cc; margin-top: 4px; }
.kpi-row { display: flex; flex-wrap: wrap; gap: 10px; }
.kpi { background: #fff; border: 1px solid #ebeef5; border-radius: 8px; padding: 8px 14px; min-width: 108px; }
.kpi-label { font-size: 11px; color: #909399; }
.kpi-value { font-size: 18px; font-weight: 600; color: var(--el-text-color-primary); }
.tbl table { width: 100%; border-collapse: collapse; background: #fff; font-size: 12px; }
.tbl th, .tbl td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #f0f2f5; }
.tbl th { color: #909399; font-weight: 500; background: #fafafa; }
.cell-key { color: var(--el-text-color-primary); }
.bars { background: #fff; border: 1px solid #ebeef5; border-radius: 8px; padding: 10px 12px; }
.bar-row { display: flex; align-items: center; gap: 8px; margin-bottom: 5px; font-size: 12px; }
.bar-label { width: 96px; flex: none; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #606266; }
.bar-track { flex: 1; height: 8px; background: #f0f2f5; border-radius: 4px; overflow: hidden; }
.bar-fill { display: block; height: 100%; background: var(--el-color-primary); border-radius: 4px; }
.bar-value { width: 56px; text-align: right; color: #909399; }
.note { background: #fff; border-left: 3px solid var(--el-color-warning); border-radius: 4px; padding: 8px 12px; font-size: 12px; color: #606266; }
.note-line { line-height: 1.8; }
.trace { margin-top: 10px; }
.trace-row { display: flex; flex-wrap: wrap; gap: 14px; font-size: 12px; color: #606266; margin-bottom: 8px; }
.trace-query { margin-bottom: 10px; }
.trace-sub { display: flex; flex-wrap: wrap; gap: 12px; font-size: 11px; color: #909399; margin-bottom: 4px; }
.sql { font-size: 11px; background: #1f2a3d; color: #d6e0f0; border-radius: 6px; padding: 10px; overflow: auto; max-height: 180px; white-space: pre-wrap; word-break: break-all; }
.trace-foot { margin-top: 4px; }
.chat-input { border-top: 1px solid #ebeef5; padding: 10px 12px; background: #fcfcfd; }
.input-actions { display: flex; align-items: center; justify-content: space-between; margin-top: 8px; }
.input-hint { font-size: 11px; color: #a8abb2; }
@media (max-width: 1100px) {
  .chat-aside { display: none; }
}
</style>
