# Etapa 1: Compilación estática de React + Vite + Tailwind CSS
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json ./
RUN npm install --no-audit --no-fund

COPY . .
RUN npm run build

# Etapa 2: Servidor Nginx Alpine ultra-ligero (~15MB RAM) con proxy reverso /api -> http://backend:8000
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
