# Device Access Gateway (nginx.conf location /api/nms/access/): REST and the terminal WebSocket. $access_upstream comes
# from upstream.inc. X-Forwarded-Host carries the browser's host:port for the gateway's WebSocket Origin check.
proxy_pass $access_upstream;
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Host $http_host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;
proxy_read_timeout 3600s;     # a terminal may be quiet for a while (the gateway's own idle timeout ends it)
proxy_send_timeout 3600s;
# rolling deployment of the access gateway (scripts/release.sh): retry a refused connection on the other container
proxy_next_upstream error timeout;
proxy_next_upstream_tries 2;
# an address cached from a container that no longer exists is not refused, it is silent: give up after 2 s (local
# network: a healthy connect takes well under a millisecond) and try the other container instead of waiting 60 s
proxy_connect_timeout 2s;
