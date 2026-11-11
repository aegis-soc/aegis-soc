FROM node:26-alpine AS build
WORKDIR /app

# 构建参数：默认留空 = 官方 registry。境内构建可在 .env 里设 AEGIS_NPM_REGISTRY，
# 或临时 --build-arg NPM_REGISTRY=https://registry.npmmirror.com
# （npm 10 会把 lockfile 里 registry.npmjs.org 的 resolved 地址替换为这里配置的源）
ARG NPM_REGISTRY=

# 按 lockfile 安装，保证镜像构建可复现
COPY package.json package-lock.json ./
RUN if [ -n "$NPM_REGISTRY" ]; then \
      echo "npm registry: $NPM_REGISTRY"; \
      npm ci --no-audit --no-fund --registry="$NPM_REGISTRY"; \
    else \
      echo "npm registry: 官方源"; \
      npm ci --no-audit --no-fund; \
    fi

COPY index.html vite.config.ts ./
COPY src ./src
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
