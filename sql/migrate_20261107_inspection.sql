-- =============================================================================
-- 迁移：AI 巡检报告表 + 角色权限（v1.1，2026-11-07）
-- 可重复执行；全新部署由 sql/init.sql + sql/seed.sql 直接创建，无需本脚本。
-- =============================================================================

USE `aegis_soc`;

CREATE TABLE IF NOT EXISTS `inspection_report` (
  `id`           BIGINT NOT NULL AUTO_INCREMENT,
  `score`        INT          NOT NULL DEFAULT 0 COMMENT '0-100 加权健康分（安全效果层权重更高）',
  `overall`      VARCHAR(16)  NOT NULL DEFAULT 'ok' COMMENT 'ok / warn / fail',
  `trigger`      VARCHAR(16)  NOT NULL DEFAULT 'manual' COMMENT 'manual / cron',
  `duration_ms`  INT          NOT NULL DEFAULT 0,
  `checks`       JSON         NULL COMMENT '各检查项结果数组',
  `metrics`      JSON         NULL COMMENT '核心 KPI 快照：处置率/缺口/持续攻击/来源覆盖/环比分数',
  `summary`      TEXT         NULL COMMENT '总结（配置 LLM 后为 AI 生成，否则规则生成）',
  `ai_enhanced`  TINYINT      NOT NULL DEFAULT 0 COMMENT '1 = 总结由大模型生成',
  `created_by`   VARCHAR(64)  NULL,
  `created_at`   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_inspect_time` (`created_at`)
) ENGINE=InnoDB COMMENT='AI 巡检报告';

-- 老库角色补齐巡检权限（seed.sql 的 ON DUPLICATE 只更新 role_name，不带权限）
UPDATE `system_role`
SET `permission_json` = '["alert:*","ioc:*","whitelist:*","device:*","plugin:*","policy:*","task:*","audit:read","dashboard:read","inspection:read","inspection:run"]'
WHERE `role_code` = 'operator'
  AND `permission_json` NOT LIKE '%inspection%';

UPDATE `system_role`
SET `permission_json` = '["alert:read","ioc:read","whitelist:read","device:read","plugin:read","policy:read","task:read","audit:read","dashboard:read","inspection:read"]'
WHERE `role_code` = 'auditor'
  AND `permission_json` NOT LIKE '%inspection%';

-- 已建表的老库补 metrics 列（MySQL 8 不支持 ADD COLUMN IF NOT EXISTS，用存储过程兜底）
DROP PROCEDURE IF EXISTS `sp_add_inspection_metrics`;
DELIMITER $$
CREATE PROCEDURE `sp_add_inspection_metrics`()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'inspection_report'
      AND COLUMN_NAME = 'metrics'
  ) THEN
    ALTER TABLE `inspection_report`
      ADD COLUMN `metrics` JSON NULL COMMENT '核心 KPI 快照' AFTER `checks`;
  END IF;
END$$
DELIMITER ;
CALL `sp_add_inspection_metrics`();
DROP PROCEDURE IF EXISTS `sp_add_inspection_metrics`;
