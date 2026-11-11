FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Shanghai \
    PIP_NO_CACHE_DIR=1

# 构建参数：默认留空 = 走官方 PyPI。
# 境内构建慢或超时（pip 拉大索引页会被掐断）时，在 .env 里设 AEGIS_PIP_INDEX，
# 由 docker-compose.yml 透传进来；也可以临时用 --build-arg 覆盖：
#   docker compose build --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple api
# 内网 HTTP 源需要额外给主机名（HTTPS 源不用填）：
#   AEGIS_PIP_TRUSTED_HOST=pypi.internal.example.com
ARG PIP_INDEX_URL=
ARG PIP_TRUSTED_HOST=

WORKDIR /app

COPY requirements.txt ./
RUN set -eu; \
    extra=""; \
    if [ -n "$PIP_INDEX_URL" ]; then extra="--index-url $PIP_INDEX_URL"; fi; \
    if [ -n "$PIP_TRUSTED_HOST" ]; then extra="$extra --trusted-host $PIP_TRUSTED_HOST"; fi; \
    echo "pip index: ${PIP_INDEX_URL:-官方 PyPI}"; \
    pip install --no-cache-dir $extra -r requirements.txt

COPY app ./app
COPY plugins ./plugins
COPY workers ./workers

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
