export default {
  title: '插件管理',
  desc: '统一设备网关，插件通过 Manifest 声明支持的 IOC 类型与能力',
  col: {
    code: '插件编码',
    name: '名称',
    version: '版本',
    iocTypes: 'IOC 类型',
    capabilities: '能力',
    desc: '说明',
    actions: '操作',
  },
  test: {
    title: '测试插件：{code}',
    hint: '连通性测试不会产生任何封禁动作。真实设备的凭据请通过设备的 credential_ref 注入。',
    run: '执行测试',
    invalidJson: '配置不是合法 JSON',
  },
}
