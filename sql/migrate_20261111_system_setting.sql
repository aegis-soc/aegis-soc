SET NAMES utf8mb4;

-- =============================================================================
-- 老库升级：系统运行期配置表 + 告警接口来源 IP 白名单
-- 执行：mysql -u<user> -p <db> < sql/migrate_20261111_system_setting.sql
-- 幂等：可重复执行。新装环境由 sql/init.sql 直接建表，无需跑本脚本。
-- =============================================================================

CREATE TABLE IF NOT EXISTS `system_setting` (
  `id`         BIGINT      NOT NULL AUTO_INCREMENT,
  `skey`       VARCHAR(64) NOT NULL COMMENT '配置键，如 alert_ip_allowlist',
  `svalue`     TEXT        NOT NULL COMMENT '配置值；列表类用换行分隔',
  `updated_by` VARCHAR(64) NULL,
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_setting_key` (`skey`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统运行期配置';

-- 默认关闭：列表为空即等于不限制（代码里 alert_ip_enforce 默认 0），
-- 这里显式落两行，便于运维直接 UPDATE 而不必先进页面。
INSERT INTO `system_setting` (`skey`, `svalue`, `updated_by`)
VALUES ('alert_ip_enforce', '0', 'migration'),
       ('alert_ip_allowlist', '', 'migration')
ON DUPLICATE KEY UPDATE `skey` = `skey`;
