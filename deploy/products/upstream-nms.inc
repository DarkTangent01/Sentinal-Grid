# Sentinel NMS web (docker-compose.products.yml): its own api plus the Device Access Gateway.
resolver 127.0.0.11 valid=10s ipv6=off;
resolver_timeout 3s;
set $api_upstream http://nms-api:8000;
set $access_upstream http://access:8100;
