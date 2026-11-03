# Shared helpers for the operational scripts (sourced, not executed). docs/SECRET_MANAGEMENT.md
# * envval KEY      one non-secret setting from .env, without `source .env` (which would export every line into the shell)
# * chq "QUERY"     run a ClickHouse query inside the clickhouse container. The password is read there from
#                   /run/secrets/clickhouse_password into a 0600 client config file on the container's /tmp, so it never
#                   appears in host or container process arguments (`ps`), shell history or this script's environment.

envval() {
  local v
  v=$(grep -m1 -E "^$1=" .env 2>/dev/null | cut -d= -f2-) || true
  v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
  printf '%s' "$v"
}

chq() {
  docker compose exec -T -e Q="$1" clickhouse sh -c '
    umask 077; f=$(mktemp); trap "rm -f \"$f\"" EXIT
    printf "<config><user><![CDATA[%s]]></user><password><![CDATA[%s]]></password></config>\n" \
      "$CLICKHOUSE_USER" "$(cat /run/secrets/clickhouse_password)" > "$f"
    clickhouse-client --config-file "$f" --query "$Q"'
}
