# Sentinel Grid web (docker-compose.products.yml): its own api. Device access is a Sentinel NMS service, so the
# /api/nms/access/ location goes to the Grid api, which has no such route (404).
resolver 127.0.0.11 valid=10s ipv6=off;
resolver_timeout 3s;
set $api_upstream http://grid-api:8000;
set $access_upstream http://grid-api:8000;
