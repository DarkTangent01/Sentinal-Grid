# $api_upstream and the resolver come from upstream.inc (Compose default; Kubernetes ConfigMap web-upstream)
proxy_pass $api_upstream;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;
proxy_read_timeout 120s;
# rolling API deployments (scripts/release.sh): while two api containers run, the name resolves to both; a connection
# refused by the container being retired is retried on the other before any byte of the request was sent (safe for
# POST too: nginx never resends a request body it already passed on)
proxy_next_upstream error timeout http_502 http_503;
proxy_next_upstream_tries 2;
# an address cached from a container that no longer exists is not refused, it is silent: give up after 2 s (local
# network: a healthy connect takes well under a millisecond) and try the other container instead of waiting 60 s
proxy_connect_timeout 2s;
proxy_next_upstream_timeout 10s;
