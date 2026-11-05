-- =============================================================================
-- 宙斯盾 AegisSoc · MySQL 8 初始化建表脚本
-- 对应《通用安全运营自动化平台需求说明书与架构方案 V1.0》附录 A（20 张表）
--
-- 约定：
--   1. 采用「逻辑外键 + 显式索引」，不建物理 FOREIGN KEY，便于后续分库、
--      数据归档与设备表迁移；关联完整性由应用层和幂等唯一键保证。
--   2. 所有涉及设备凭据的字段仅存 credential_ref（环境变量名），不存明文。
--   3. 时间统一 DATETIME(3)，字符集 utf8mb4 / utf8mb4_unicode_ci。
--   4. 本文件由 docker-entrypoint-initdb.d 在首次初始化时执行；业务表结构与
--      ORM 定义（backend/app/models.py）保持一致。
-- =============================================================================

CREATE DATABASE IF NOT EXISTS `aegis_soc`
  DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `aegis_soc`;

-- ---------------------------------------------------------------------------
-- A.1 权限与用户
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `system_role` (
  `id`            BIGINT NOT NULL AUTO_INCREMENT,
  `role_code`     VARCHAR(32)  NOT NULL COMMENT 'admin / operator / auditor',
  `role_name`     VARCHAR(64)  NOT NULL,
  `permission_json` JSON      NULL COMMENT '接口级权限清单，如 ["*"] 或 ["ioc:read","task:retry"]',
  `description`   VARCHAR(255) NULL,
  `created_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_role_code` (`role_code`)
) ENGINE=InnoDB COMMENT='系统角色';

CREATE TABLE IF NOT EXISTS `system_user` (
  `id`                  BIGINT NOT NULL AUTO_INCREMENT,
  `username`            VARCHAR(64)  NOT NULL,
  `password_hash`       VARCHAR(255) NOT NULL COMMENT 'bcrypt',
  `nickname`            VARCHAR(64)  NULL,
  `role_code`           VARCHAR(32)  NOT NULL DEFAULT 'auditor',
  `status`              TINYINT      NOT NULL DEFAULT 1 COMMENT '1 启用 / 0 禁用',
  `must_change_password` TINYINT     NOT NULL DEFAULT 0 COMMENT '首次登录强制改密',
  `last_login_at`       DATETIME(3)  NULL,
  `created_at`          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_username` (`username`),
  KEY `idx_role` (`role_code`)
) ENGINE=InnoDB COMMENT='系统用户';

-- ---------------------------------------------------------------------------
-- A.2 标准化事件与告警
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `security_event` (
  `id`               BIGINT NOT NULL AUTO_INCREMENT,
  `source_system`    VARCHAR(64)  NOT NULL COMMENT 'graylog / generic / waf / ips',
  `source_event_id`  VARCHAR(128) NOT NULL COMMENT '来源侧原始事件 ID',
  `event_type`       VARCHAR(64)  NULL,
  `severity`         VARCHAR(16)  NULL COMMENT 'critical / high / medium / low / info',
  `raw_payload`      LONGTEXT     NULL COMMENT '原始事件报文，仅用于追溯，检索仍在 Graylog',
  `occurred_at`      DATETIME(3)  NULL,
  `created_at`       DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_source_event` (`source_system`, `source_event_id`),
  KEY `idx_event_time` (`created_at`)
) ENGINE=InnoDB COMMENT='标准化安全事件';

CREATE TABLE IF NOT EXISTS `alert_event` (
  `id`               BIGINT NOT NULL AUTO_INCREMENT,
  `alert_id`         VARCHAR(128) NOT NULL COMMENT '全局唯一告警 ID，用于幂等去重',
  `source_system`    VARCHAR(64)  NOT NULL DEFAULT 'graylog',
  `source_event_id`  VARCHAR(128) NULL,
  `title`            VARCHAR(255) NULL,
  `severity`         VARCHAR(16)  NULL,
  `risk_level`       VARCHAR(16)  NULL COMMENT 'critical / high / medium / low',
  `confidence`       DECIMAL(5,2) NULL COMMENT '0.00 - 100.00',
  `src_ips`          JSON         NULL,
  `ioc_candidates`   JSON         NULL COMMENT '[{type,value,confidence}]',
  `raw_payload`      LONGTEXT     NULL,
  `status`           VARCHAR(24)  NOT NULL DEFAULT 'pending'
                     COMMENT 'pending / processed / whitelisted / ignored / failed',
  `dedupe_key`       VARCHAR(128) NULL,
  `process_msg`      VARCHAR(500) NULL,
  `received_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_at`       DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_alert_id` (`alert_id`),
  KEY `idx_dedupe_key` (`dedupe_key`),
  KEY `idx_alert_status` (`status`),
  KEY `idx_alert_received` (`received_at`)
) ENGINE=InnoDB COMMENT='告警事件（去重与处置追踪）';

-- ---------------------------------------------------------------------------
-- A.3 IOC 威胁指标
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `ioc_indicator` (
  `id`                BIGINT NOT NULL AUTO_INCREMENT,
  `ioc_type`          VARCHAR(16)  NOT NULL COMMENT 'IP / DOMAIN / URL / HASH',
  `ioc_value`         VARCHAR(512) NOT NULL COMMENT '原始值',
  `normalized_value`  VARCHAR(512) NOT NULL COMMENT '归一化值（IP 压缩、域名小写去尾点）',
  `status`            VARCHAR(16)  NOT NULL DEFAULT 'active' COMMENT 'active / rejected / whitelisted / expired / disabled',
  `confidence`        DECIMAL(5,2) NULL,
  `risk_level`        VARCHAR(16)  NULL,
  `expire_at`         DATETIME(3)  NULL COMMENT 'NULL = 永久；到期由 Celery Beat 生成解封任务',
  `tags`              JSON         NULL,
  `remark`            VARCHAR(500) NULL,
  `source_type`       VARCHAR(24)  NOT NULL DEFAULT 'UNKNOWN' COMMENT 'IPS / WAF / ZTNA / TI / AV / FW / NTA / GRAYLOG / MANUAL / API',
  `source_detail`     VARCHAR(128) NULL COMMENT '来源原始标识：设备名 / stream / vendor',
  `alert_id`          VARCHAR(128) NULL COMMENT '关联告警 ID',
  `reject_reason`     VARCHAR(255) NULL COMMENT '被拦截或豁免的原因',
  `source_count`      INT          NOT NULL DEFAULT 0,
  `created_by`        VARCHAR(64)  NULL,
  `created_at`        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_ioc_value` (`ioc_type`, `normalized_value`),
  KEY `idx_ioc_status` (`status`),
  KEY `idx_ioc_expire` (`expire_at`),
  KEY `idx_ioc_type` (`ioc_type`),
  KEY `idx_ioc_source` (`source_type`)
) ENGINE=InnoDB COMMENT='IOC 主表（黑名单流水，同值不合并）';

CREATE TABLE IF NOT EXISTS `ioc_ip_detail` (
  `id`             BIGINT NOT NULL AUTO_INCREMENT,
  `ioc_id`         BIGINT NOT NULL,
  `ip_bin`         VARBINARY(16) NOT NULL COMMENT 'IPv4/IPv6 定长二进制，支持网段包含比对',
  `prefix_len`     SMALLINT      NOT NULL DEFAULT 32 COMMENT 'IPv4 默认 32，IPv6 默认 128',
  `address_family` TINYINT       NOT NULL DEFAULT 4 COMMENT '4 / 6',
  `cidr`           VARCHAR(64)   NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ioc_ip` (`ioc_id`),
  KEY `idx_ip_bin` (`ip_bin`)
) ENGINE=InnoDB COMMENT='IP 型 IOC 明细';

CREATE TABLE IF NOT EXISTS `ioc_domain_detail` (
  `id`           BIGINT NOT NULL AUTO_INCREMENT,
  `ioc_id`       BIGINT NOT NULL,
  `match_mode`   VARCHAR(16) NOT NULL DEFAULT 'exact' COMMENT 'exact / subdomain / wildcard',
  `root_domain`  VARCHAR(255) NULL,
  `is_wildcard`  TINYINT NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ioc_domain` (`ioc_id`),
  KEY `idx_root_domain` (`root_domain`)
) ENGINE=InnoDB COMMENT='域名型 IOC 明细';

CREATE TABLE IF NOT EXISTS `ioc_source` (
  `id`               BIGINT NOT NULL AUTO_INCREMENT,
  `ioc_id`           BIGINT NOT NULL,
  `source_system`    VARCHAR(64)  NOT NULL,
  `source_event_id`  VARCHAR(128) NULL,
  `first_seen_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `last_seen_at`     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `hit_count`        INT         NOT NULL DEFAULT 1,
  `raw_ref`          VARCHAR(255) NULL,
  `created_at`       DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ioc_source` (`ioc_id`, `source_system`, `source_event_id`),
  KEY `idx_ioc_source_ref` (`source_event_id`)
) ENGINE=InnoDB COMMENT='IOC 多来源记录（禁止单来源失效误删封禁依据）';

CREATE TABLE IF NOT EXISTS `ioc_device_binding` (
  `id`                BIGINT NOT NULL AUTO_INCREMENT,
  `ioc_id`            BIGINT NOT NULL,
  `device_id`         BIGINT NOT NULL,
  `last_operation`    VARCHAR(16) NULL COMMENT 'BLOCK / UNBLOCK',
  `last_task_status`  VARCHAR(24) NULL,
  `last_task_id`      BIGINT      NULL,
  `last_sync_at`      DATETIME(3) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ioc_device` (`ioc_id`, `device_id`),
  KEY `idx_binding_device` (`device_id`)
) ENGINE=InnoDB COMMENT='IOC 与设备绑定关系（每设备独立执行状态）';

CREATE TABLE IF NOT EXISTS `ip_whitelist` (
  `id`           BIGINT NOT NULL AUTO_INCREMENT,
  `ip_value`     VARCHAR(64)   NOT NULL COMMENT '单 IP 或 CIDR 的网络地址',
  `cidr`         VARCHAR(64)   NULL COMMENT '原始 CIDR 文本',
  `ip_bin`       VARBINARY(16) NOT NULL,
  `prefix_len`   SMALLINT      NOT NULL DEFAULT 32,
  `cidr_flag`    TINYINT       NOT NULL DEFAULT 0 COMMENT '1=CIDR 段',
  `remark`       VARCHAR(500)  NULL,
  `status`       TINYINT       NOT NULL DEFAULT 1,
  `created_by`   VARCHAR(64)   NULL,
  `created_at`   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_whitelist` (`ip_value`, `prefix_len`),
  KEY `idx_wl_ip_bin` (`ip_bin`)
) ENGINE=InnoDB COMMENT='IP 白名单（独立存储，禁止被自动封禁）';

-- ---------------------------------------------------------------------------
-- A.4 设备与插件
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `security_device` (
  `id`             BIGINT NOT NULL AUTO_INCREMENT,
  `device_code`    VARCHAR(64)  NOT NULL,
  `name`           VARCHAR(128) NOT NULL,
  `vendor`         VARCHAR(64)  NULL,
  `model`          VARCHAR(64)  NULL,
  `region`         VARCHAR(64)  NULL,
  `plugin_code`    VARCHAR(64)  NOT NULL,
  `config_json`    JSON         NULL COMMENT '插件配置；敏感项用 credential_ref 引用环境变量',
  `credential_ref` VARCHAR(128) NULL COMMENT '环境变量名，禁止存明文凭据',
  `capabilities`   JSON         NULL COMMENT '[{ioc_type,capability}]',
  `status`         VARCHAR(16)  NOT NULL DEFAULT 'unknown' COMMENT 'online / offline / unknown / disabled',
  `auto_dispatch`  TINYINT      NOT NULL DEFAULT 1 COMMENT '是否允许自动下发',
  `last_check_at`  DATETIME(3)  NULL,
  `created_at`     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_device_code` (`device_code`),
  KEY `idx_device_plugin` (`plugin_code`),
  KEY `idx_device_status` (`status`)
) ENGINE=InnoDB COMMENT='安全设备资产';

CREATE TABLE IF NOT EXISTS `device_plugin` (
  `id`           BIGINT NOT NULL AUTO_INCREMENT,
  `plugin_code`  VARCHAR(64)  NOT NULL,
  `plugin_name`  VARCHAR(128) NOT NULL,
  `version`      VARCHAR(32)  NULL,
  `manifest`     JSON         NULL COMMENT '能力声明：ioc_types / capabilities / config_schema',
  `enabled`      TINYINT      NOT NULL DEFAULT 1,
  `builtin`      TINYINT      NOT NULL DEFAULT 1,
  `description`  VARCHAR(500) NULL,
  `created_at`   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_plugin_code` (`plugin_code`)
) ENGINE=InnoDB COMMENT='设备插件注册表';

CREATE TABLE IF NOT EXISTS `device_capability` (
  `id`           BIGINT NOT NULL AUTO_INCREMENT,
  `device_id`    BIGINT NOT NULL,
  `plugin_code`  VARCHAR(64) NOT NULL,
  `ioc_type`     VARCHAR(16) NOT NULL COMMENT 'IP / DOMAIN',
  `capability`   VARCHAR(16) NOT NULL COMMENT 'BLOCK / UNBLOCK / QUERY',
  `enabled`      TINYINT NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_capability` (`device_id`, `ioc_type`, `capability`),
  KEY `idx_cap_plugin` (`plugin_code`)
) ENGINE=InnoDB COMMENT='设备能力矩阵（IOC 类型隔离）';

-- ---------------------------------------------------------------------------
-- A.5 策略与编排
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `automation_policy` (
  `id`               BIGINT NOT NULL AUTO_INCREMENT,
  `policy_code`      VARCHAR(64)  NOT NULL,
  `name`             VARCHAR(128) NOT NULL,
  `description`      VARCHAR(500) NULL,
  `enabled`          TINYINT      NOT NULL DEFAULT 1,
  `priority`         INT          NOT NULL DEFAULT 100 COMMENT '数值越小优先级越高',
  `conditions`       JSON         NULL COMMENT '告警字段匹配条件',
  `threshold_count`  INT          NOT NULL DEFAULT 1 COMMENT '时间窗内命中次数阈值',
  `window_minutes`   INT          NOT NULL DEFAULT 10,
  `min_confidence`   DECIMAL(5,2) NOT NULL DEFAULT 0.00,
  `risk_levels`      JSON         NULL,
  `target_plugins`   JSON         NULL COMMENT '限定插件，空=全部可用',
  `block_duration`   INT          NOT NULL DEFAULT 7200 COMMENT '封禁时长（秒），0=永久',
  `require_approval` TINYINT      NOT NULL DEFAULT 0,
  `auto_dispatch`    TINYINT      NOT NULL DEFAULT 1,
  `created_at`       DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`       DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_policy_code` (`policy_code`),
  KEY `idx_policy_priority` (`priority`)
) ENGINE=InnoDB COMMENT='自动化封禁策略';

CREATE TABLE IF NOT EXISTS `policy_device_rel` (
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `policy_id`  BIGINT NOT NULL,
  `device_id`  BIGINT NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_policy_device` (`policy_id`, `device_id`)
) ENGINE=InnoDB COMMENT='策略目标设备（空=按能力自动匹配全部可用设备）';

CREATE TABLE IF NOT EXISTS `workflow_definition` (
  `id`             BIGINT NOT NULL AUTO_INCREMENT,
  `workflow_code`  VARCHAR(64) NOT NULL,
  `name`           VARCHAR(128) NOT NULL,
  `dag_json`       JSON        NULL COMMENT 'v1.1 可视化 DAG 编排定义',
  `enabled`        TINYINT     NOT NULL DEFAULT 0,
  `version`        INT         NOT NULL DEFAULT 1,
  `created_at`     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_workflow_code` (`workflow_code`)
) ENGINE=InnoDB COMMENT='工作流定义（v1.0 建表占位，v1.1 实现引擎）';

-- ---------------------------------------------------------------------------
-- A.6 任务、日志与审批
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `device_task` (
  `id`            BIGINT NOT NULL AUTO_INCREMENT,
  `task_no`       VARCHAR(64)  NOT NULL,
  `ioc_id`        BIGINT       NULL,
  `ioc_type`      VARCHAR(16)  NOT NULL DEFAULT 'IP',
  `ioc_value`     VARCHAR(512) NOT NULL,
  `device_id`     BIGINT       NOT NULL,
  `plugin_code`   VARCHAR(64)  NOT NULL,
  `operation`     VARCHAR(16)  NOT NULL COMMENT 'BLOCK / UNBLOCK / QUERY',
  `task_status`   VARCHAR(24)  NOT NULL DEFAULT 'PENDING'
                  COMMENT 'PENDING / RUNNING / SUCCESS / FAILED / RETRY / CANCELED / APPROVING / REJECTED',
  `retry_count`   INT          NOT NULL DEFAULT 0,
  `max_retry`     INT          NOT NULL DEFAULT 3,
  `next_retry_at` DATETIME(3)  NULL,
  `priority`      INT          NOT NULL DEFAULT 5,
  `request_id`    VARCHAR(64)  NOT NULL COMMENT '同一次告警处置的幂等批次',
  `result_msg`    VARCHAR(1000) NULL,
  `expire_at`     DATETIME(3)  NULL,
  `created_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `started_at`    DATETIME(3)  NULL,
  `finished_at`   DATETIME(3)  NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_task_no` (`task_no`),
  UNIQUE KEY `uk_task_idempotent` (`ioc_id`, `device_id`, `operation`, `request_id`),
  KEY `idx_task_status` (`task_status`),
  KEY `idx_task_next_retry` (`next_retry_at`),
  KEY `idx_task_expire` (`expire_at`),
  KEY `idx_task_ioc` (`ioc_id`),
  KEY `idx_task_created` (`created_at`)
) ENGINE=InnoDB COMMENT='设备下发任务（幂等 + 重试 + 到期解封）';

CREATE TABLE IF NOT EXISTS `device_task_log` (
  `id`              BIGINT NOT NULL AUTO_INCREMENT,
  `task_id`         BIGINT NOT NULL,
  `attempt`         INT    NOT NULL DEFAULT 1,
  `request_payload` LONGTEXT NULL COMMENT '脱敏后的请求报文',
  `response_payload` LONGTEXT NULL COMMENT '设备返回原始报文',
  `http_status`     INT    NULL,
  `cost_ms`         INT    NULL,
  `success`         TINYINT NOT NULL DEFAULT 0,
  `error_msg`       VARCHAR(1000) NULL,
  `created_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_tasklog_task` (`task_id`)
) ENGINE=InnoDB COMMENT='任务执行日志（等保审计追溯）';

CREATE TABLE IF NOT EXISTS `approval_record` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `task_id`     BIGINT NULL,
  `ioc_id`      BIGINT NULL,
  `applicant`   VARCHAR(64) NULL,
  `approver`    VARCHAR(64) NULL,
  `status`      VARCHAR(16) NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING / APPROVED / REJECTED',
  `reason`      VARCHAR(500) NULL,
  `created_at`  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `decided_at`  DATETIME(3) NULL,
  PRIMARY KEY (`id`),
  KEY `idx_approval_status` (`status`)
) ENGINE=InnoDB COMMENT='高危封禁审批记录（v1.0 最简两态）';

-- ---------------------------------------------------------------------------
-- A.7 审计
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `operation_audit` (
  `id`           BIGINT NOT NULL AUTO_INCREMENT,
  `operator`     VARCHAR(64)  NOT NULL DEFAULT 'system',
  `role_code`    VARCHAR(32)  NULL,
  `op_type`      VARCHAR(64)  NOT NULL COMMENT 'ALERT_RECEIVE / IOC_CREATE / WHITELIST_HIT / TASK_DISPATCH ...',
  `target_type`  VARCHAR(32)  NULL,
  `target_id`    VARCHAR(64)  NULL,
  `content`      TEXT         NULL,
  `client_ip`    VARCHAR(64)  NULL,
  `created_at`   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_audit_operator` (`operator`),
  KEY `idx_audit_type` (`op_type`),
  KEY `idx_audit_time` (`created_at`)
) ENGINE=InnoDB COMMENT='全链路操作审计';
