# $api_upstream and the resolver come from upstream.inc (Compose default; Kubernetes ConfigMap web-upstream)
proxy_pass $api_upstream;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;
proxy_read_timeout 120s;
