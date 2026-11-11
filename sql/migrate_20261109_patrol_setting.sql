-- 老库补建日志巡检配置表（幂等）
-- 执行：mysql -u root -p aegis_soc < sql/migrate_20261109_patrol_setting.sql
-- 日志巡检配置（单行 id=1）：页面可改，环境变量只做首次默认值
CREATE TABLE IF NOT EXISTS `patrol_setting` (
  `id`               TINYINT      NOT NULL DEFAULT 1,
  `enabled`          TINYINT      NOT NULL DEFAULT 0 COMMENT '1=启用定时巡检',
  `mcp_url`          VARCHAR(255) NULL COMMENT 'Graylog MCP 端点，如 https://graylog/api/mcp',
  `mcp_token`        VARCHAR(255) NULL COMMENT 'Graylog API Token（接口只回掩码）',
  `mcp_auth`         VARCHAR(16)  NOT NULL DEFAULT 'token' COMMENT 'token / bearer / basic / none / raw',
  `mcp_tool`         VARCHAR(64)  NOT NULL DEFAULT 'search_messages',
  `mcp_stream_tool`  VARCHAR(64)  NOT NULL DEFAULT 'list_streams',
  `mcp_args`         TEXT         NULL COMMENT '参数模板，留空=按工具 inputSchema 自动映射',
  `streams`          JSON         NULL COMMENT '[{name,label,stream_id,query}]',
  `interval_seconds` INT          NOT NULL DEFAULT 300,
  `overlap_seconds`  INT          NOT NULL DEFAULT 60,
  `max_records`      INT          NOT NULL DEFAULT 2000,
  `timeout_seconds`  INT          NOT NULL DEFAULT 30,
  `repeat_hours`     INT          NOT NULL DEFAULT 24,
  `mode`             VARCHAR(16)  NOT NULL DEFAULT 'dry-run',
  `updated_by`       VARCHAR(64)  NULL,
  `updated_at`       DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB COMMENT='日志巡检配置（单行）';

