# both stages pinned by digest (multi-arch index); Dependabot proposes updates
FROM node:22.23.4-alpine3.24@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
# PRODUCT=grid / nms builds that product's app alone (docker-compose.products.yml); empty builds the combined app
ARG PRODUCT=""
RUN if [ -n "$PRODUCT" ]; then npm run "build:$PRODUCT" && rm -rf dist && mv "dist-$PRODUCT" dist; else npm run build; fi

FROM nginx:1.31.0-alpine@sha256:2f07d83bf561b506400dc183b1b2003803e39efbd22451f848adaba14d28c7c7
# files are root-owned and read-only to the server (uid 101): a compromised worker cannot rewrite the UI or its config
# apk upgrade: security fixes published after the pinned base image
RUN apk upgrade --no-cache && rm /etc/nginx/conf.d/default.conf
# UI layout (frontend/publish-ui.sh): /srv/ui/releases/<release> holds index.html and the unhashed public files,
# /srv/ui/assets the content-hashed bundles shared by releases, /srv/ui/current the release nginx serves. In Compose a
# named volume ("ui") is mounted here and receives new releases without restarting nginx; on first use Docker seeds the
# volume from this image. Owned by uid 10101 (the publisher); nginx (uid 101 / WEB_UID) only reads.
COPY --from=build /src/dist /srv/ui/releases/image
COPY publish-ui.sh /usr/local/bin/publish-ui
RUN mv /srv/ui/releases/image/assets /srv/ui/assets && (cd /srv/ui/assets && ls -1) > /srv/ui/releases/image/.assets \
    && ln -s releases/image /srv/ui/current && chown -R 10101:101 /srv/ui && chmod -R u=rwX,go=rX /srv/ui \
    && chmod 0755 /usr/local/bin/publish-ui \
    && mkdir -p /target && chown 10101:101 /target   # ui-release mount point: a new "ui" volume inherits this owner
ARG BUILD_VERSION=dev
LABEL org.opencontainers.image.version=$BUILD_VERSION
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
