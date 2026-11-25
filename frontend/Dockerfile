# both stages pinned by digest (multi-arch index); Dependabot proposes updates
FROM node:22.23.4-alpine3.24@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
# PRODUCT=grid / nms builds that product's app alone (docker-compose.products.yml); empty builds the combined app
ARG PRODUCT=""
RUN if [ -n "$PRODUCT" ]; then npm run "build:$PRODUCT" && rm -rf dist && mv "dist-$PRODUCT" dist; else npm run build; fi

FROM nginx:1.30.6-alpine@sha256:0e52bd054126cdc040b1276c0af347aeb02a41b9cfe305d6094767ac30e97949
# files are root-owned and read-only to the server (uid 101): a compromised worker cannot rewrite the UI or its config
# apk upgrade: security fixes published after the pinned base image
RUN apk upgrade --no-cache && rm /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
COPY nginx-main.conf /etc/nginx/nginx.conf
COPY nginx.conf /etc/nginx/conf.d/siem.conf
COPY proxy_params.inc /etc/nginx/conf.d/proxy_params.inc
COPY upstream.inc /etc/nginx/conf.d/upstream.inc
COPY proxy_access.inc /etc/nginx/conf.d/proxy_access.inc
COPY security_headers.inc /etc/nginx/conf.d/security_headers.inc
USER 101:101
EXPOSE 8080 8443
# no entrypoint scripts (they try to rewrite files in /etc/nginx); exec form so nginx receives SIGTERM / SIGQUIT
ENTRYPOINT []
CMD ["nginx", "-g", "daemon off;"]
STOPSIGNAL SIGQUIT
