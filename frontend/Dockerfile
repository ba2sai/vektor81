# Etapa 1: Compilación estática de React + Vite + Tailwind CSS
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json ./
RUN npm install --no-audit --no-fund

COPY . .
RUN npm run build

# Etapa 2: Servidor Nginx Alpine ultra-ligero con proxy configurable /api/v2 y /api/v1
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

# Permite sobreescribir http://control-plane:8787 mediante CONTROL_PLANE_UPSTREAM al arrancar
RUN printf '#!/bin/sh\nset -e\nif [ -n "${CONTROL_PLANE_UPSTREAM:-}" ]; then\n  sed -i "s|http://control-plane:8787|${CONTROL_PLANE_UPSTREAM%/}|g" /etc/nginx/conf.d/default.conf\nfi\n' > /docker-entrypoint.d/10-control-plane-upstream.sh \
    && chmod +x /docker-entrypoint.d/10-control-plane-upstream.sh

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
