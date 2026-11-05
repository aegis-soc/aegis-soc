-- ---------------------------------------------------------------------------
-- 迁移：黑名单改为流水表（同值不合并）+ 来源字段（2026-11-05）
--
-- 背景：
--   1) 原 uk_ioc(ioc_type, normalized_value) 唯一键会把同一 IP 的多次命中
--      合并成一条记录，丢失「本次是什么时候、被哪类设备、由哪条告警加的」；
--   2) 部分封禁设备不支持按 IP 覆盖式解封，只能等 5 天自然失效，
--      同一 IP 再次命中必须新增一条记录，否则无法判断哪次下发还在生效；
--   3) 被内网/保留地址规则拦截的 IOC 也要在黑名单列表里可见，
--      只是状态为 rejected / whitelisted，不下发任务。
--
-- 执行方式（生产库，先备份）：
--   mysql -u aegis -p aegis_soc < sql/migrate_20261105_ioc_history.sql
-- 本脚本可重复执行：每一步都先判断列/索引是否存在。
-- ---------------------------------------------------------------------------

-- 1) 新增来源字段
SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND COLUMN_NAME = 'source_type') = 0,
  'ALTER TABLE `ioc_indicator` ADD COLUMN `source_type` VARCHAR(24) NOT NULL DEFAULT ''UNKNOWN'' COMMENT ''IPS / WAF / ZTNA / TI / AV / FW / NTA / GRAYLOG / MANUAL / API'' AFTER `remark`',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND COLUMN_NAME = 'source_detail') = 0,
  'ALTER TABLE `ioc_indicator` ADD COLUMN `source_detail` VARCHAR(128) NULL COMMENT ''来源原始标识：设备名 / stream / vendor'' AFTER `source_type`',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND COLUMN_NAME = 'alert_id') = 0,
  'ALTER TABLE `ioc_indicator` ADD COLUMN `alert_id` VARCHAR(128) NULL COMMENT ''关联告警 ID'' AFTER `source_detail`',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND COLUMN_NAME = 'reject_reason') = 0,
  'ALTER TABLE `ioc_indicator` ADD COLUMN `reject_reason` VARCHAR(255) NULL COMMENT ''状态原因：拦截/豁免理由'' AFTER `alert_id`',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 2) 去掉同值唯一键，改成普通索引（允许同一 IP 多条流水）
SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND INDEX_NAME = 'uk_ioc') > 0,
  'ALTER TABLE `ioc_indicator` DROP INDEX `uk_ioc`',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND INDEX_NAME = 'idx_ioc_value') = 0,
  'ALTER TABLE `ioc_indicator` ADD KEY `idx_ioc_value` (`ioc_type`, `normalized_value`)',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND INDEX_NAME = 'idx_ioc_source') = 0,
  'ALTER TABLE `ioc_indicator` ADD KEY `idx_ioc_source` (`source_type`)',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 3) 历史数据回填来源：告警自动创建标记 GRAYLOG，其余视为手工
UPDATE `ioc_indicator`
   SET `source_type` = CASE WHEN `remark` LIKE '由告警%' THEN 'GRAYLOG' ELSE 'MANUAL' END
 WHERE `source_type` = 'UNKNOWN';

-- 4) 状态注释补充新取值
ALTER TABLE `ioc_indicator`
  MODIFY COLUMN `status` VARCHAR(16) NOT NULL DEFAULT 'active'
  COMMENT 'active / rejected / whitelisted / expired / disabled';
