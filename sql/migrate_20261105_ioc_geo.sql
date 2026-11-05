-- ---------------------------------------------------------------------------
-- 迁移：黑名单增加 IP 归属地快照字段（2026-11-05）
--
-- 背景：
--   需要在黑名单列表里直接看到「中国 / 广东省·深圳市」这类归属地，
--   用于快速判断攻击来源是国内还是境外、哪几个省份最集中。
--   归属地采用 ip2region 离线库（不再依赖 ipip.net），库文件约 11 MB，
--   由 scripts/fetch_geoip.py 下载，服务启动后自动热加载。
--
-- 为什么存快照而不是每次实时查询：
--   1) 库每月更新，历史记录应保留当时的归属，便于复盘；
--   2) 列表接口不依赖库文件，库缺失/未下载时旧记录依旧可读。
--   存量数据用 scripts/backfill_geo.py 回填（可重复执行）。
--
-- 执行方式（生产库，先备份）：
--   mysql -u aegis -p aegis_soc < sql/migrate_20261105_ioc_geo.sql
-- 本脚本可重复执行：每一步都先判断列/索引是否存在。
-- ---------------------------------------------------------------------------

SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND COLUMN_NAME = 'geo_country') = 0,
  'ALTER TABLE `ioc_indicator` ADD COLUMN `geo_country` VARCHAR(64) NULL COMMENT ''归属国家（中文）'' AFTER `reject_reason`',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND COLUMN_NAME = 'geo_province') = 0,
  'ALTER TABLE `ioc_indicator` ADD COLUMN `geo_province` VARCHAR(64) NULL COMMENT ''归属省份'' AFTER `geo_country`',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND COLUMN_NAME = 'geo_city') = 0,
  'ALTER TABLE `ioc_indicator` ADD COLUMN `geo_city` VARCHAR(64) NULL COMMENT ''归属城市'' AFTER `geo_province`',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND COLUMN_NAME = 'geo_isp') = 0,
  'ALTER TABLE `ioc_indicator` ADD COLUMN `geo_isp` VARCHAR(64) NULL COMMENT ''运营商'' AFTER `geo_city`',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ioc_indicator' AND INDEX_NAME = 'idx_ioc_geo') = 0,
  'ALTER TABLE `ioc_indicator` ADD KEY `idx_ioc_geo` (`geo_country`)',
  'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 回填由 Python 完成（需要读 xdb）：
--   cd backend && python ../scripts/backfill_geo.py
