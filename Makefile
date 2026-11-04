SHELL := /bin/bash
COMPOSE := docker compose

.PHONY: help up down restart build logs ps init-db test lint smoke clean shell-api shell-db

help:
	@echo "宙斯盾 AegisSoc 快捷命令"
	@echo "  make up        启动全部服务"
	@echo "  make down      停止并保留数据卷"
	@echo "  make build     重新构建镜像"
	@echo "  make logs      查看实时日志"
	@echo "  make ps        查看容器状态"
	@echo "  make test      运行后端测试"
	@echo "  make smoke     本地冒烟（compileall + pytest + 前端构建）"
	@echo "  make clean     停止服务并删除数据卷（危险）"

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart

build:
	$(COMPOSE) build --no-cache

logs:
	$(COMPOSE) logs -f --tail=200

ps:
	$(COMPOSE) ps

init-db:
	$(COMPOSE) exec -T mysql sh -c 'mysql -uroot -p"$$MYSQL_ROOT_PASSWORD" < /docker-entrypoint-initdb.d/../init.sql' || true

test:
	cd backend && python -m pytest -q

lint:
	cd backend && python -m compileall -q app plugins workers

smoke: lint test
	cd frontend && npm run build

shell-api:
	$(COMPOSE) exec api sh

shell-db:
	$(COMPOSE) exec mysql mysql -uroot -p aegis_soc

clean:
	$(COMPOSE) down -v
