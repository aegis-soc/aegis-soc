-- 老库补建「人机对话」两张表（幂等，可重复执行）
-- 执行：mysql -u root -p aegis_soc < sql/migrate_20261110_chat.sql
-- 说明：数据只增不改，不影响现有表；本地 SQLite 由 init_db() 的 create_all 自动建表

-- 会话：一次"开个新对话"一条
CREATE TABLE IF NOT EXISTS `chat_session` (
  `id`            BIGINT       NOT NULL AUTO_INCREMENT,
  `username`      VARCHAR(64)  NOT NULL,
  `title`         VARCHAR(120) NOT NULL DEFAULT '新对话' COMMENT '首问截断',
  `message_count` INT          NOT NULL DEFAULT 0,
  `created_at`    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_chat_session_user` (`username`)
) ENGINE=InnoDB COMMENT='人机对话会话';

-- 消息：一问一答各一条。payload 存渲染块，dsl 存当次解析结果，便于复盘
CREATE TABLE IF NOT EXISTS `chat_message` (
  `id`         BIGINT      NOT NULL AUTO_INCREMENT,
  `session_id` BIGINT      NOT NULL,
  `role`       VARCHAR(16) NOT NULL COMMENT 'user / assistant',
  `content`    TEXT        NOT NULL COMMENT '问题原文或结论正文',
  `blocks`     JSON        NULL COMMENT '渲染块：[{type,title,...}]',
  `route`      VARCHAR(16) NULL COMMENT 'db / log / clarify',
  `dsl`        JSON        NULL COMMENT '当次解析出的 DSL，复盘用',
  `trace`      JSON        NULL COMMENT '编译后的 SQL / MCP 检索说明',
  `elapsed_ms` INT         NOT NULL DEFAULT 0,
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_chat_msg_session` (`session_id`)
) ENGINE=InnoDB COMMENT='人机对话消息';

-- 权限补齐：已有的 operator / auditor 角色追加 chat:ask（admin 是 *，无需处理）
-- 如果角色被改过、权限是自定义的，请按实际需要手工追加。
UPDATE `system_role`
   SET `permission_json` = JSON_ARRAY_APPEND(`permission_json`, '$', 'chat:ask')
 WHERE `role_code` IN ('operator', 'auditor')
   AND JSON_CONTAINS(`permission_json`, '"*"') = 0
   AND JSON_CONTAINS(`permission_json`, '"chat:ask"') = 0;
