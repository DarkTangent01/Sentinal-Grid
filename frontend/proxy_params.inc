# A variable makes nginx resolve "api" through the resolver below (every 10 s) instead of once at startup, so a
# redeployed api container with a new IP is picked up without restarting nginx.
set $api_upstream http://api:8000;
proxy_pass $api_upstream;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;
proxy_read_timeout 120s;
