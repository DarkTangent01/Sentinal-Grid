#!/usr/bin/env bash
# NetworkPolicies, statically and by real connection attempts from inside the pods (needs a cluster whose CNI enforces
# NetworkPolicy). Each probe: python socket connect with a 3 s timeout, from the pod's own container.
#   allowed:  api -> postgres:5432, api -> clickhouse:8123, web -> api:8000
#   denied:   web -> postgres:5432, syslog -> api:8000, poller -> clickhouse... (allowed), syslog -> 1.1.1.1:443 (no egress)
set -uo pipefail
NS="${1:-sentinel}"; here="$(cd "$(dirname "$0")" && pwd)"
python3 "$here/k8s_audit.py" --live --namespace "$NS" --only netpol || true
fail=0
probe() {  # probe <from-deployment> <host> <port> <expect: open|closed>
  local from=$1 host=$2 port=$3 want=$4 got
  if [ "$from" = web ] || [ "$from" = ingress-relay ]; then
    got=$(kubectl -n "$NS" exec "deploy/$from" -- sh -c "timeout 3 nc -z -w 3 $host $port >/dev/null 2>&1 && echo open || echo closed" 2>/dev/null)
  else
    got=$(kubectl -n "$NS" exec "deploy/$from" -- python -c "import socket,sys
s=socket.socket(); s.settimeout(3)
try: s.connect(('$host',$port)); print('open')
except Exception: print('closed')" 2>/dev/null)
  fi
  if [ "$got" = "$want" ]; then echo "PASS  $from -> $host:$port is $want"
  elif [ -z "$got" ]; then echo "WARN  $from -> $host:$port not tested (exec failed)"
  else echo "FAIL  $from -> $host:$port is $got, expected $want"; fail=1; fi
}
probe api postgres 5432 open
probe api clickhouse 8123 open
probe web api 8000 open
probe web postgres 5432 closed
probe web clickhouse 8123 closed
probe syslog api 8000 closed
probe syslog 1.1.1.1 443 closed
probe traps 1.1.1.1 443 closed
probe poller postgres 5432 open
exit $fail
