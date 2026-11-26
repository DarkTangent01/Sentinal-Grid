# Where the api is and how nginx finds it (included by nginx.conf in the TLS server block). A variable (see
# proxy_params.inc) makes nginx resolve the name through this resolver every 2 s instead of once at startup, so a
# re-created api with a new address is picked up without restarting nginx. nginx's resolver ignores DNS search domains.
# This default is Docker Compose: Docker's embedded DNS and the service name "api". Kubernetes replaces the file with
# the ConfigMap web-upstream (cluster DNS, api.sentinel.svc.cluster.local); a Podman lab mounts its network's DNS.
resolver 127.0.0.11 valid=2s ipv6=off;   # 2 s: a retired api container leaves the rotation quickly (scripts/release.sh)
resolver_timeout 3s;
set $api_upstream http://api:8000;
set $access_upstream http://access:8100;     # Device Access Gateway (docker-compose service "access")
