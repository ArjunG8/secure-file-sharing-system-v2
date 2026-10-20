# Owner: M10. Production-style image for the `tls` Compose profile:
# builds the frontend once, then serves the static files from nginx (no Vite dev server).
# Build context: repository root (see docker-compose.yml).

FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# Same-origin API: the browser calls https://<host>/api/v1, proxied by nginx.
ENV VITE_API_BASE_URL=/api/v1
RUN npm run build

FROM nginx:1.27-alpine
COPY infra/nginx/nginx.conf /etc/nginx/nginx.conf
COPY --from=frontend /build/dist /usr/share/nginx/html
EXPOSE 80 443
