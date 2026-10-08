# Builds one of the two static apps (web/ or bank-demo/) and serves it with nginx.
FROM node:20-alpine AS build
ARG APP_DIR
ARG VITE_API_BASE=http://localhost:8000
ENV VITE_API_BASE=${VITE_API_BASE}
WORKDIR /src
COPY fixtures/api /fixtures/api
COPY ${APP_DIR}/package*.json ./
RUN npm ci
COPY ${APP_DIR}/ ./
RUN npm run build

FROM nginx:1.27-alpine
COPY deploy/nginx-spa.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 80
