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
