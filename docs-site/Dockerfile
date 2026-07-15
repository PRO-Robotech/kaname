# syntax=docker/dockerfile:1.6
# Build stage — Docusaurus static build
FROM node:22-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

# .dockerignore excludes node_modules/build/.docusaurus/.git
COPY . .
RUN npm run build

# Runtime — nginx serves the static Docusaurus output (NO proxy_pass).
# nginx-unprivileged: runs as non-root uid 101, listens on 8080, pid → /tmp — so it
# works under runAsNonRoot + readOnlyRootFilesystem (see deploy/templates/deployment.yaml).
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY deploy/default.conf /etc/nginx/conf.d/default.conf

# Explicit non-root USER (trivy DS-0002: don't run containers as root).
USER 101

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
