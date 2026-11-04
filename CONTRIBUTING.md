# 贡献指南

感谢你为 宙斯盾 AegisSoc 做贡献！

## 分支与提交

1. Fork 仓库，新建分支：`feature/xxx`、`fix/xxx`、`plugin/xxx`
2. 提交信息使用英文祈使句，例如 `add sangfor ips plugin`、`fix whitelist cidr check`
3. 提交前执行：

```bash
cd backend && pytest -q
cd frontend && npm run build
```

4. 填写 PR 说明：变更内容、影响范围、测试结果、是否涉及安全逻辑

## 代码规范

- **后端**：Python 3.12+，FastAPI + SQLAlchemy 2.0 + Pydantic v2；遵循 PEP 8，类型注解必填
- **前端**：Vue 3 `<script setup>` + Element Plus，禁止引入未经评审的重型依赖
- **安全**：任何设备地址、账号、口令、API Key 一律不得硬编码；新增插件必须参数化并通过 `docs/security.md` 自查
- **审计**：涉及白名单、策略、设备、任务状态变更的操作必须写 `operation_audit`

## 设备插件规范

新增插件请阅读 [docs/plugin-dev.md](docs/plugin-dev.md)，并满足：

1. 继承 `plugins.base.BasePlugin`，声明 `Manifest`（`ioc_types` / `capabilities` / `config_schema`）
2. 实现 `test_connection` / `block` / `unblock` / `query_status`，统一返回 `PluginResult`
3. 自带连通性测试、README、参数说明与超时控制
4. 不得在插件内持久化凭据；敏感配置用 `credential_ref` 引用环境变量
5. 补充单元测试（用 `mock` 或本地 stub，禁止依赖真实设备）

## 安全披露

发现安全漏洞请不要公开提 issue，请通过项目维护者私下反馈。

## 许可证

贡献即表示你同意以 [Apache License 2.0](LICENSE) 发布你的贡献。
