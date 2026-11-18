export default {
  risk: {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
  },
  alertStatus: {
    pending: 'Pending',
    processed: 'Processed',
    whitelisted: 'Allowlisted',
    ignored: 'Ignored',
    failed: 'Failed',
  },
  taskStatus: {
    PENDING: 'Pending',
    RUNNING: 'Running',
    SUCCESS: 'Succeeded',
    FAILED: 'Failed',
    RETRY: 'Retry queued',
    CANCELED: 'Canceled',
    APPROVING: 'Awaiting approval',
    REJECTED: 'Rejected',
  },
  deviceStatus: {
    online: 'Online',
    offline: 'Offline',
    unknown: 'Unknown',
  },
  operation: {
    BLOCK: 'Block',
    UNBLOCK: 'Unblock',
    QUERY: 'Query',
  },
}
