SET NAMES utf8mb4;

-- =============================================================================
-- 宙斯盾 AegisSoc · 初始化种子数据
-- 由 docker-entrypoint-initdb.d 在首次建库后执行；全部为占位/示例值，无真实凭据。
-- 管理员账号不在此文件硬编码（避免提交口令哈希），由 backend/app/bootstrap.py 在
-- API 首次启动时按 BOOTSTRAP_ADMIN_PASSWORD 生成，并置 must_change_password=1。
-- =============================================================================

USE `aegis_soc`;

-- ---------- 角色 ----------
INSERT INTO `system_role` (`role_code`, `role_name`, `permission_json`, `description`) VALUES
  ('admin',    '系统管理员', '["*"]', '全部权限，含用户管理与系统设置'),
  ('operator', '安全运营',   '["alert:*","ioc:*","whitelist:*","device:*","plugin:*","policy:*","task:*","audit:read","dashboard:read","inspection:read","inspection:run"]', '日常告警处置、IOC 与策略管理'),
  ('auditor',  '只读审计员', '["alert:read","ioc:read","whitelist:read","device:read","plugin:read","policy:read","task:read","audit:read","dashboard:read","inspection:read"]', '仅查看，禁止任何写操作')
ON DUPLICATE KEY UPDATE `role_name` = VALUES(`role_name`);

-- ---------- 内置插件注册表 ----------
INSERT INTO `device_plugin` (`plugin_code`, `plugin_name`, `version`, `manifest`, `enabled`, `builtin`, `description`) VALUES
  ('mock', 'Mock 测试设备', '1.0.0',
   '{"ioc_types":["IP","DOMAIN"],"capabilities":["BLOCK","UNBLOCK","QUERY"],"config_schema":{},"description":"只记录任务不真实下发，用于闭环演示与单元测试"}',
   1, 1, '模拟设备插件，不调用任何真实设备'),
  ('http_generic', '通用 HTTP 设备', '1.0.0',
   '{"ioc_types":["IP","DOMAIN"],"capabilities":["BLOCK","UNBLOCK","QUERY"],"config_schema":{"base_url":"string","method":"POST|DELETE|GET","headers":"object","body_template":"string","timeout":"int"}}',
   1, 1, '低代码 REST 插件，通过 URL/方法/请求体模板适配任意设备'),
  ('ssh_firewall', 'SSH 防火墙（H3C / 华为）', '1.0.0',
   '{"ioc_types":["IP"],"capabilities":["BLOCK","UNBLOCK"],"config_schema":{"host":"string","port":"int","username":"string","credential_ref":"string","vendor":"h3c|huawei","timeout_minutes":"int"}}',
   1, 1, '由现有生产 paramiko 脚本抽象，全参数化，凭据仅通过环境变量引用'),
  ('sangfor_ips', '深信服 IPS 全局黑名单', '1.0.0',
   '{"ioc_types":["IP"],"capabilities":["BLOCK","UNBLOCK"],"config_schema":{"base_url":"string","username":"string","credential_ref":"string","verify_ssl":"bool"}}',
   1, 1, '登录 → SHA256 签名 → 黑名单插入 → applyconfig 配置生效'),
  ('paloalto_fw', 'Palo Alto PAN-OS', '1.0.0',
   '{"ioc_types":["IP"],"capabilities":["BLOCK","UNBLOCK"],"config_schema":{"base_url":"string","credential_ref":"string","vsys":"string","tag_name":"string","verify_ssl":"bool","timeout":"int"},"description":"user-id 注册 IP 到 DAG tag，即时生效、无需 commit"}',
   1, 1, 'PAN-OS 9.1+ XML API，user-id + Dynamic Address Group 即时封禁'),
  ('qiming_fw', '启明星辰 天清汉马 USG', '1.0.0',
   '{"ioc_types":["IP"],"capabilities":["BLOCK","UNBLOCK"],"config_schema":{"base_url":"string","username":"string","credential_ref":"string","login_path":"string","token_path":"string","block_path":"string","unblock_path":"string","save_path":"string","verify_ssl":"bool"},"description":"Web API 登录鉴权 → 黑名单下发 → 可选保存生效"}',
   1, 1, '天清汉马 Web API，路径与报文全参数化，保存失败判失败'),
  ('qiming_ips', '启明星辰 天清IPS', '1.0.0',
   '{"ioc_types":["IP","DOMAIN"],"capabilities":["BLOCK"],"config_schema":{"base_url":"string","username":"string","credential_ref":"string","block_type":"int","end_time_minutes":"int","enable":"int","password_hash":"string","sha256_uppercase":"bool","verify_ssl":"bool"},"description":"REST v3：SHA256 口令登录 → JWT → block_policy 封堵，到期由设备自动失效"}',
   1, 1, 'IPS *080+：登录 SHA256 摘要、JWT 缓存、type=4 封禁 IP、end_time 分钟'),
  ('aliyun_waf_v3', '阿里云 WAF 3.0', '1.0.0',
   '{"ioc_types":["IP"],"capabilities":["BLOCK","UNBLOCK"],"config_schema":{"instance_id":"string","template_id":"int","credential_ref":"string","rule_name":"string","action":"string","max_entries":"int","max_rules":"int","auto_create_rule":"bool","endpoint":"string"},"description":"IP 黑名单：取全量 → 合并 → 整表回写，单规则 200 条自动分片"}',
   1, 1, 'WAF 3.0 ip_blacklist：整表回写、200 条/规则自动分片、写入后回读校验')
ON DUPLICATE KEY UPDATE `plugin_name` = VALUES(`plugin_name`);

-- ---------- 示例设备（mock，开箱即可跑通闭环） ----------
INSERT INTO `security_device`
  (`device_code`, `name`, `vendor`, `model`, `region`, `plugin_code`, `config_json`, `credential_ref`, `capabilities`, `status`, `auto_dispatch`)
VALUES
  ('mock-device-01', '演示设备（Mock）', 'AegisSoc', 'mock', 'lab', 'mock',
   '{"mode":"log"}', NULL,
   '[{"ioc_type":"IP","capability":"BLOCK"},{"ioc_type":"IP","capability":"UNBLOCK"},{"ioc_type":"DOMAIN","capability":"BLOCK"}]',
   'online', 1)
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);

SET @mock_device_id = (SELECT `id` FROM `security_device` WHERE `device_code` = 'mock-device-01');

INSERT INTO `device_capability` (`device_id`, `plugin_code`, `ioc_type`, `capability`, `enabled`) VALUES
  (@mock_device_id, 'mock', 'IP', 'BLOCK', 1),
  (@mock_device_id, 'mock', 'IP', 'UNBLOCK', 1),
  (@mock_device_id, 'mock', 'IP', 'QUERY', 1),
  (@mock_device_id, 'mock', 'DOMAIN', 'BLOCK', 1)
ON DUPLICATE KEY UPDATE `enabled` = 1;

-- ---------- 默认自动化策略 ----------
INSERT INTO `automation_policy`
  (`policy_code`, `name`, `description`, `enabled`, `priority`, `conditions`,
   `threshold_count`, `window_minutes`, `min_confidence`, `risk_levels`, `target_plugins`,
   `block_duration`, `require_approval`, `auto_dispatch`)
VALUES
  ('default-auto-block', '默认自动封禁', 'Graylog 高危告警命中后自动封禁 2 小时；白名单与内网地址强制豁免',
   1, 100, '{}', 1, 10, 60.00,
   '["critical","high","medium"]', '[]', 7200, 0, 1)
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);

SET @default_policy_id = (SELECT `id` FROM `automation_policy` WHERE `policy_code` = 'default-auto-block');

INSERT INTO `policy_device_rel` (`policy_id`, `device_id`)
VALUES (@default_policy_id, @mock_device_id)
ON DUPLICATE KEY UPDATE `device_id` = VALUES(`device_id`);

-- ---------- 示例白名单（全部使用 RFC5737 文档地址，非真实资产） ----------
INSERT INTO `ip_whitelist` (`ip_value`, `cidr`, `ip_bin`, `prefix_len`, `cidr_flag`, `remark`, `status`, `created_by`) VALUES
  ('192.0.2.0',    '192.0.2.0/24',    UNHEX('C0000200000000000000000000000000'), 24, 1, 'RFC5737 示例网段：演示 CIDR 白名单包含检查', 1, 'system'),
  ('198.51.100.10', NULL,              UNHEX('C633640A000000000000000000000000'), 32, 0, 'RFC5737 示例地址：演示单 IP 白名单豁免', 1, 'system')
ON DUPLICATE KEY UPDATE `remark` = VALUES(`remark`);
