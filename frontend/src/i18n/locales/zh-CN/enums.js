export default {
  risk: {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
  },
  alertStatus: {
    pending: '待处理',
    processed: '已处置',
    whitelisted: '白名单放行',
    ignored: '已忽略',
    failed: '处理失败',
  },
  taskStatus: {
    PENDING: '待执行',
    RUNNING: '执行中',
    SUCCESS: '成功',
    FAILED: '失败',
    RETRY: '待重试',
    CANCELED: '已取消',
    APPROVING: '待审批',
    REJECTED: '已拒绝',
  },
  deviceStatus: {
    online: '在线',
    offline: '离线',
    unknown: '未知',
  },
  operation: {
    BLOCK: '封禁',
    UNBLOCK: '解封',
    QUERY: '查询',
  },
}
