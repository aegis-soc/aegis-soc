-- 老库补建日志巡检两张表（幂等，可重复执行）
-- 执行：mysql -u root -p aegis_soc < sql/migrate_20261108_patrol.sql

日志巡检（P0）：通过 MCP 只读 Graylog 三流日志，找 Graylog 规则漏掉的攻击源
-- =============================================================================
CREATE TABLE IF NOT EXISTS `patrol_run` (
  `id`              BIGINT NOT NULL AUTO_INCREMENT,
  `trigger`         VARCHAR(16)  NOT NULL DEFAULT 'cron' COMMENT 'cron / manual',
  `mode`            VARCHAR(16)  NOT NULL DEFAULT 'dry-run' COMMENT 'dry-run / assist / auto',
  `status`          VARCHAR(16)  NOT NULL DEFAULT 'ok' COMMENT 'ok / degraded / failed / skipped',
  `window_start`    DATETIME(3) NOT NULL COMMENT '本轮日志窗口起点（UTC）',
  `window_end`      DATETIME(3) NOT NULL COMMENT '本轮日志窗口终点（UTC）',
  `duration_ms`     INT          NOT NULL DEFAULT 0,
  `fetched`         INT          NOT NULL DEFAULT 0 COMMENT '拉取的日志条数',
  `candidate_count` INT          NOT NULL DEFAULT 0 COMMENT '候选 IP 数',
  `would_block`     INT          NOT NULL DEFAULT 0 COMMENT '通过闸门的 IP 数',
  `blocked`         INT          NOT NULL DEFAULT 0 COMMENT '实际下发数（P0 恒为 0）',
  `summary`         JSON         NULL COMMENT '流状态/规则命中/处置分布/Top IP',
  `error`           TEXT         NULL,
  `created_by`      VARCHAR(64)  NULL,
  `created_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_patrol_time` (`created_at`)
) ENGINE=InnoDB COMMENT='日志巡检批次';

CREATE TABLE IF NOT EXISTS `patrol_candidate` (
  `id`              BIGINT NOT NULL AUTO_INCREMENT,
  `run_id`          BIGINT       NOT NULL,
  `ip_value`        VARCHAR(64)  NOT NULL,
  `streams`         VARCHAR(64)  NULL COMMENT '命中流，逗号分隔',
  `hits`            INT          NOT NULL DEFAULT 0,
  `severity`        TINYINT      NOT NULL DEFAULT 0 COMMENT '1-5',
  `rules`           JSON         NULL COMMENT '[{key,name,count}]',
  `decision`        VARCHAR(24)  NOT NULL DEFAULT 'would_block' COMMENT 'would_block / skipped_*',
  `decision_reason` VARCHAR(255) NULL,
  `first_seen`      DATETIME(3) NULL,
  `last_seen`       DATETIME(3) NULL,
  `created_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_patrol_run` (`run_id`),
  KEY `idx_patrol_ip` (`ip_value`)
) ENGINE=InnoDB COMMENT='日志巡检候选 IP';
