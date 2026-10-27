FROM node:22.12.0-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.27.3-alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/siem.conf
COPY proxy_params.inc /etc/nginx/conf.d/proxy_params.inc
COPY security_headers.inc /etc/nginx/conf.d/security_headers.inc
EXPOSE 80 443
