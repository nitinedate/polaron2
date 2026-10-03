# --- Build stage ---
FROM node:20-alpine AS build
WORKDIR /app

# Empty = same-origin /api (nginx proxies to gateway). Set only for external API hosts.
ARG VITE_API_BASE=
ARG VITE_DEFAULT_TENANT=platform
ARG VITE_AETHERIS_SERVICE=unified
ARG VITE_VULN_MODULE_ENABLED=true
ENV VITE_API_BASE=$VITE_API_BASE
ENV VITE_DEFAULT_TENANT=$VITE_DEFAULT_TENANT
ENV VITE_AETHERIS_SERVICE=$VITE_AETHERIS_SERVICE
ENV VITE_VULN_MODULE_ENABLED=$VITE_VULN_MODULE_ENABLED

COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

# --- Runtime stage ---
FROM nginx:1.27-alpine AS runtime
RUN apk add --no-cache wget
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN sed -i 's/\r$//' /docker-entrypoint.sh && chmod +x /docker-entrypoint.sh
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
