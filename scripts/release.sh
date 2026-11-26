#!/usr/bin/env bash
# Service-by-service builds and health-gated deployments on the Sentinel server (docs/deployment-guide.md).
# Runs in the deployment directory on the server (scripts/deploy.sh calls it after syncing the code).
#
#   ./scripts/release.sh deploy <target>... [--no-cache] [--allow-destructive]
#   ./scripts/release.sh rollback <service>
#   ./scripts/release.sh status
#   ./scripts/release.sh history [N]
#   ./scripts/release.sh build <backend|web|ansible|ingress|tacacs> [--no-cache]
#   ./scripts/release.sh adopt <service>...      a service still on an image from before release.sh: record it as current
#
# Targets:
#   ui        web UI release: published into the "ui" volume and switched atomically; nginx keeps running (no downtime)
#   api       rolling: a second api starts, must pass /api/ready, then the old one drains and stops (no downtime)
#   poller    rolling, one replica at a time (device leases prevent duplicate polls; monitoring continues)
#   worker | access | syslog | traps | flows | ansible     replaced one at a time (stop, then start; seconds)
#   edge      the nginx container itself (only when nginx / its configuration changes; about 1-3 s)
#   ingress | tacacs     the syslog front end / TACACS+ server (explicit only)
#   migrate   database migrations only (expand-only check first)
#   backend   migrate + api + poller + worker + access + syslog + traps + flows
#   all       backend + ansible + ui (+ edge / ingress / tacacs when their sources changed)
#   auto      whatever changed since the running images were built (default for scripts/deploy.sh)
#
# Every image is tagged <UTC date>-<source hash> and labelled with its source hash: an unchanged source is never rebuilt,
# and each service's tag lives in .env (<SERVICE>_TAG), so other services keep theirs. The previous image is kept for
# rollback (the last KEEP_IMAGES per repository). Infrastructure (postgres, clickhouse, the "ui" / data volumes) is
# never touched by a deployment. State, history and logs: deploy/state/.
set -euo pipefail
cd "$(dirname "$0")/.."

STATE=deploy/state
mkdir -p "$STATE"
chmod 0755 "$STATE"
LOG="$STATE/deploy.log"
HIST="$STATE/history.jsonl"
KEEP_IMAGES="${KEEP_IMAGES:-5}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-180}"
DNS_SETTLE="${DNS_SETTLE:-5}"               # nginx re-resolves the api name every 2 s (frontend/upstream.inc)
NO_CACHE=""; ALLOW_DESTRUCTIVE=""
TEST_FAIL="${DEPLOY_TEST_FAIL:-}"           # deployment tests only: build | migrate | health:<service>

declare -A REPO=([backend]=fortisiem-backend [web]=fortisiem-web [ansible]=fortisiem-ansible [ingress]=fortisiem-ingress [tacacs]=fortisiem-tacacs)
declare -A IMAGE_OF=([migrate]=backend [api]=backend [worker]=backend [access]=backend [poller]=backend [syslog]=backend [traps]=backend
                     [flows]=backend [ansible]=ansible [ui]=web [edge]=web [ingress]=ingress [tacacs]=tacacs)
declare -A VAR_OF=([migrate]=MIGRATE_TAG [api]=API_TAG [worker]=WORKER_TAG [access]=ACCESS_TAG [poller]=POLLER_TAG [syslog]=SYSLOG_TAG
                   [traps]=TRAPS_TAG [flows]=FLOWS_TAG [ansible]=ANSIBLE_TAG [ui]=UI_TAG [edge]=WEB_TAG [ingress]=INGRESS_TAG [tacacs]=TACACS_TAG)
declare -A COMPOSE_SVC=([edge]=web [ui]=ui-release)
declare -A STRATEGY=([api]=rolling [poller]=rolling [worker]=recreate [access]=recreate [syslog]=recreate [traps]=recreate [flows]=recreate
                     [ansible]=recreate [edge]=edge [ingress]=recreate [tacacs]=recreate [ui]=ui [migrate]=migrate)
BACKEND_SERVICES=(migrate api poller worker access syslog traps flows)

exec 9>"$STATE/.lock"
flock -n 9 || { echo "[release] another deployment is running" >&2; exit 1; }
exec > >(while IFS= read -r l; do printf '%s %s\n' "$(date -u +%FT%TZ)" "$l"; done | tee -a "$LOG") 2>&1

log() { echo "[release] $*"; }
die() { echo "[release] FAILED: $*" >&2; exit 1; }
dc() { docker compose "$@"; }
svc_of() { echo "${COMPOSE_SVC[$1]:-$1}"; }
now() { date -u +%FT%TZ; }
safe() { tr -cd 'A-Za-z0-9._:/ +-' <<<"$1" | cut -c1-200; }

record() {  # service from to result seconds note
  printf '{"ts":"%s","service":"%s","from":"%s","to":"%s","result":"%s","duration_s":%s,"note":"%s"}\n' \
    "$(now)" "$(safe "$1")" "$(safe "$2")" "$(safe "$3")" "$(safe "$4")" "${5:-0}" "$(safe "${6:-}")" >> "$HIST"
}

# ---- tags: .env holds <SERVICE>_TAG lines (docker-compose.yml interpolates them); deploy/state mirrors them -------------
env_get() { grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true; }
current_tag() {
  local v; v="$(env_get "$1")"
  if [ -z "$v" ] && [ "${IMAGE_OF[$2]:-}" = backend ]; then v="$(env_get BACKEND_TAG)"; fi
  echo "${v:-1.0.0}"
}
set_tag() {  # VAR value
  local old; old="$(env_get "$1")"
  if grep -qE "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else
    grep -q '^# ---- deployed image tags' .env || printf '\n# ---- deployed image tags (scripts/release.sh; do not edit by hand) ----\n' >> .env
    echo "$1=$2" >> .env
  fi
  touch "$STATE/versions.prev.env"
  if [ -n "$old" ] && [ "$old" != "$2" ]; then
    sed -i "/^$1=/d" "$STATE/versions.prev.env"; echo "$1=$old" >> "$STATE/versions.prev.env"
  fi
  grep -E '^[A-Z]+_TAG=' .env > "$STATE/versions.env" || true
}

# ---- builds --------------------------------------------------------------------------------------------------------
context_of() { case "$1" in backend|ansible) echo backend;; web) echo frontend;; ingress) echo deploy/ingress;; tacacs) echo deploy/tacacs;; esac; }
dockerfile_of() { case "$1" in ansible) echo backend/Dockerfile.ansible;; *) echo "$(context_of "$1")/Dockerfile";; esac; }
source_hash() {  # image → hash of everything its build reads
  local ctx; ctx="$(context_of "$1")"
  find "$ctx" -type f ! -path '*/node_modules/*' ! -path '*/__pycache__/*' ! -name '*.pyc' ! -path "$ctx/dist*" ! -path '*/.pytest_cache/*' -print0 \
    | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-12
}
edge_hash() { cat frontend/nginx-main.conf frontend/nginx.conf frontend/*.inc frontend/Dockerfile | sha256sum | cut -c1-12; }
label_of() { docker image inspect "$1" --format "{{index .Config.Labels \"$2\"}}" 2>/dev/null || true; }
tag_for_hash() { docker images "${REPO[$1]}" --filter "label=sentinel.source=$2" --format '{{.Tag}}' | grep -v '<none>' | head -1; }

build() {  # image → prints the tag (built only when no image of the same source exists)
  local img="$1" h tag t0 blog
  h="$(source_hash "$img")"
  if [ -z "$NO_CACHE" ] && tag="$(tag_for_hash "$img" "$h")" && [ -n "$tag" ]; then
    log "build $img: source $h already built as ${REPO[$img]}:$tag" >&2; echo "$tag"; return 0
  fi
  tag="$(date -u +%Y%m%d-%H%M)-$h"
  blog="$STATE/build-$img-$tag.log"
  t0=$(date +%s)
  log "build $img → ${REPO[$img]}:$tag (log: $blog)" >&2
  local extra=()
  [ "$TEST_FAIL" = build ] && extra+=(--target does-not-exist)
  # shellcheck disable=SC2086
  if ! docker build $NO_CACHE "${extra[@]}" -f "$(dockerfile_of "$img")" --label "sentinel.source=$h" --label "sentinel.edge=$(edge_hash)" \
      --label "sentinel.component=$img" --build-arg "BUILD_VERSION=$tag" -t "${REPO[$img]}:$tag" "$(context_of "$img")" > "$blog" 2>&1; then
    tail -25 "$blog" >&2
    record "build:$img" "-" "$tag" failed "$(( $(date +%s) - t0 ))" "build failed; nothing deployed"
    die "build of $img failed (running services untouched)"
  fi
  log "built ${REPO[$img]}:$tag in $(( $(date +%s) - t0 )) s" >&2
  echo "$tag"
}

# ---- health -------------------------------------------------------------------------------------------------------
cstate() { docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$1" 2>/dev/null || echo "gone gone"; }
wait_healthy() {  # container [timeout] [service]
  local c="$1" to="${2:-$HEALTH_TIMEOUT}" svc="${3:-}" t=0 s
  while [ "$t" -lt "$to" ]; do
    s="$(cstate "$c")"
    if [ "$TEST_FAIL" = "health:$svc" ]; then sleep 3; return 1; fi
    case "$s" in
      "running healthy"|"running none") return 0;;
      exited*|dead*|gone*) return 1;;
    esac
    sleep 3; t=$((t + 3))
  done
  return 1
}
edge_ok() {  # the public path: nginx → api, and the UI index
  dc exec -T web wget -q -O /dev/null --no-check-certificate https://127.0.0.1:8443/api/ready 2>/dev/null \
    && dc exec -T web wget -q -O /dev/null --no-check-certificate https://127.0.0.1:8443/ 2>/dev/null
}
ids() { dc ps -q "$1" 2>/dev/null | sort; }

# ---- strategies ---------------------------------------------------------------------------------------------------
deploy_migrate() {
  local tag="$1" var=MIGRATE_TAG old; old="$(current_tag "$var" migrate)"
  local t0=$(date +%s)
  log "migrate: expand-only check with $tag"
  local check=0
  MIGRATE_TAG="$tag" dc run --rm --no-deps -T migrate python -m app.migrate_check $ALLOW_DESTRUCTIVE || check=$?
  if [ "$check" -ne 0 ]; then record migrate "$old" "$tag" refused "$(( $(date +%s) - t0 ))" "migration check exit $check"; die "migration check refused (exit $check); nothing changed"; fi
  log "migrate: applying"
  local cmd=(python -m app.migrate)
  [ "$TEST_FAIL" = migrate ] && cmd=(python -c "raise SystemExit('simulated migration failure')")
  if ! MIGRATE_TAG="$tag" dc run --rm --no-deps -T migrate "${cmd[@]}"; then
    record migrate "$old" "$tag" failed "$(( $(date +%s) - t0 ))" "migration failed; services untouched"
    die "migration failed: no service was changed (fix, then redeploy; migrations are transactional per revision)"
  fi
  set_tag "$var" "$tag"
  record migrate "$old" "$tag" ok "$(( $(date +%s) - t0 ))"
}

replace_one() {  # service old-container check(0/1) → replaces one container with one running the service's current tag
  local svc="$1" c="$2" check="$3" before after new n
  before="$(ids "$svc")"; n=$(echo "$before" | grep -c .)
  dc up -d --no-deps --no-recreate --scale "$svc=$((n + 1))" "$svc" >/dev/null
  after="$(ids "$svc")"
  new="$(comm -13 <(echo "$before") <(echo "$after") | head -1)"
  [ -n "$new" ] || { log "$svc: no new container appeared"; return 1; }
  # the api joins nginx's network only once it is healthy and warm: a fresh process answers its first requests slowly
  local fnet=""
  if [ "$svc" = api ]; then
    fnet="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{println $k}}{{end}}' "$new" | grep -E '_frontend$' | head -1)"
    [ -n "$fnet" ] && docker network disconnect "$fnet" "$new" >/dev/null 2>&1 || true
  fi
  log "$svc: ${new:0:12} started with $(current_tag "${VAR_OF[$svc]}" "$svc"); waiting for it to be healthy"
  if ! wait_healthy "$new" "$HEALTH_TIMEOUT" "$svc"; then
    docker logs --tail 30 "$new" 2>&1 | sed 's/^/    /' || true
    docker rm -f "$new" >/dev/null; return 1
  fi
  if [ -n "$fnet" ]; then
    for _ in 1 2 3 4 5; do docker exec "$new" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/ready', timeout=10)" >/dev/null 2>&1 || true; done
    docker network connect --alias api "$fnet" "$new" || { docker rm -f "$new" >/dev/null; return 1; }
    log "api: ${new:0:12} warmed and added to nginx's network"
  fi
  [ "$svc" = api ] && { log "api: both versions serve; letting nginx pick up the new address (${DNS_SETTLE} s)"; sleep "$DNS_SETTLE"; }
  log "$svc: draining and stopping ${c:0:12} (in-flight requests finish, up to 30 s)"
  docker stop -t 30 "$c" >/dev/null
  if [ "$check" = 1 ] && [ "$svc" = api ]; then
    sleep "$DNS_SETTLE"                         # the stopped address leaves nginx's cache before the public check
    if ! edge_ok; then
      log "$svc: public health check failed after the switch: restoring ${c:0:12}"
      docker start "$c" >/dev/null; wait_healthy "$c" 120 || true; docker rm -f "$new" >/dev/null; return 1
    fi
  fi
  docker rm "$c" >/dev/null
}

revert_rolling() {  # service tag → every container not on that tag is replaced by one that is (best effort, no public check)
  local svc="$1" tag="$2" img c
  img="${REPO[${IMAGE_OF[$svc]}]}:$tag"
  set_tag "${VAR_OF[$svc]}" "$tag"
  for c in $(ids "$svc"); do
    [ "$(docker inspect -f '{{.Config.Image}}' "$c" 2>/dev/null)" = "$img" ] && continue
    log "$svc: returning ${c:0:12} to $tag"
    replace_one "$svc" "$c" 0 || log "$svc: could not return ${c:0:12} to $tag: check by hand (release.sh status)"
  done
}

deploy_rolling() {  # service tag — start the new container next to each old one, health-gate, drain, stop the old one
  local svc="$1" tag="$2" var="${VAR_OF[$1]}" old n t0 c
  old="$(current_tag "$var" "$svc")"
  [ "$old" = "$tag" ] && [ -z "$FORCE" ] && { log "$svc already runs $tag"; return 0; }
  t0=$(date +%s)
  local before; before="$(ids "$svc")"; n=$(echo "$before" | grep -c . || true)
  [ "$n" -ge 1 ] || { log "$svc is not running: starting it"; set_tag "$var" "$tag"; dc up -d --no-deps "$svc"; record "$svc" "$old" "$tag" ok 0 "started"; return; }
  set_tag "$var" "$tag"
  for c in $before; do
    if ! replace_one "$svc" "$c" 1; then
      log "$svc: switch failed: returning every replica to $old"
      revert_rolling "$svc" "$old"
      record "$svc" "$old" "$tag" "rolled back" "$(( $(date +%s) - t0 ))" "failed during the rolling switch; all replicas back on $old"
      die "$svc: rolled back to $old"
    fi
  done
  # bring the service to its configured replica count (e.g. api: API_REPLICAS) with the new version
  local want; want="$(desired_replicas "$svc")"
  if [ "$want" -gt "$n" ]; then
    log "$svc: scaling to $want replicas"
    dc up -d --no-deps --no-recreate --scale "$svc=$want" "$svc" >/dev/null
    for c in $(ids "$svc"); do wait_healthy "$c" "$HEALTH_TIMEOUT" "$svc" || die "$svc: added replica unhealthy"; done
  fi
  record "$svc" "$old" "$tag" ok "$(( $(date +%s) - t0 ))" "rolling, $n container(s)"
  log "$svc: now on $tag"
}
desired_replicas() { dc config --format json 2>/dev/null | jq -r --arg s "$1" '.services[$s].deploy.replicas // 1' 2>/dev/null || echo 1; }

deploy_recreate() {  # service tag — stop, start the new version, health-gate, roll back on failure
  local svc="$1" tag="$2" var="${VAR_OF[$1]}" cs old t0 c ok=1
  cs="$(svc_of "$1")"
  old="$(current_tag "$var" "$svc")"
  [ "$old" = "$tag" ] && [ -z "$FORCE" ] && { log "$svc already runs $tag"; return 0; }
  t0=$(date +%s)
  set_tag "$var" "$tag"
  log "$svc: replacing ($old → $tag)"
  dc up -d --no-deps --force-recreate "$cs" >/dev/null || ok=0
  for c in $(ids "$cs"); do wait_healthy "$c" "$HEALTH_TIMEOUT" "$svc" || ok=0; done
  if [ "$ok" = 0 ]; then
    for c in $(ids "$cs"); do docker logs --tail 30 "$c" 2>&1 | sed 's/^/    /' || true; done
    log "$svc: new version unhealthy: restoring $old"
    set_tag "$var" "$old"; dc up -d --no-deps --force-recreate "$cs" >/dev/null
    for c in $(ids "$cs"); do wait_healthy "$c" 180 || true; done
    record "$svc" "$old" "$tag" "rolled back" "$(( $(date +%s) - t0 ))" "unhealthy after start"
    die "$svc: rolled back to $old"
  fi
  local d=$(( $(date +%s) - t0 ))
  record "$svc" "$old" "$tag" ok "$d" "replaced; interruption about ${d} s or less"
  log "$svc: now on $tag (${d} s)"
  case "$svc" in syslog|ingress) ./scripts/fix-syslog-conntrack.sh >/dev/null 2>&1 || true;; esac
}

ui_release_of() { dc run --rm --no-deps -T ui-release --list 2>/dev/null | sed -n 's/^current: //p'; }
deploy_ui() {  # tag — publish the release into the ui volume and switch; nginx keeps running
  local tag="$1" old t0; old="$(env_get UI_TAG)"; t0=$(date +%s)
  local prev; prev="$(ui_release_of || true)"
  if [ "$prev" = "$tag" ] && [ -z "$FORCE" ]; then log "ui already serves $tag"; return 0; fi
  log "ui: publishing release $tag (previous: ${prev:-none})"
  UI_TAG="$tag" dc run --rm --no-deps -T ui-release "$tag" || { record ui "$prev" "$tag" failed "$(( $(date +%s) - t0 ))" "publish failed"; die "ui publish failed: the previous release keeps being served"; }
  if [ -n "$(ids web)" ] && ! edge_ok; then
    log "ui: the new release does not load: switching back to $prev"
    [ -n "$prev" ] && UI_TAG="$tag" dc run --rm --no-deps -T ui-release --switch "$prev" || true
    record ui "$prev" "$tag" "rolled back" "$(( $(date +%s) - t0 ))" "index check failed"
    die "ui: rolled back to $prev"
  fi
  set_tag UI_TAG "$tag"
  record ui "${prev:-$old}" "$tag" ok "$(( $(date +%s) - t0 ))" "switched atomically; no restart"
  log "ui: serving $tag"
}

deploy_edge() {  # tag — nginx itself: test the configuration with the new image, then replace the container
  local tag="$1" old t0; old="$(current_tag WEB_TAG edge)"; t0=$(date +%s)
  [ "$old" = "$tag" ] && [ -z "$FORCE" ] && { log "edge already runs $tag"; return 0; }
  WEB_TAG="$tag" dc run --rm --no-deps -T --entrypoint nginx web -t || die "edge: nginx configuration test failed with $tag; the running proxy is untouched"
  # the ui volume must hold a release before nginx serves from it (first switch to volume-based releases)
  [ -n "$(ui_release_of || true)" ] || deploy_ui "$tag"
  deploy_recreate edge "$tag"
}

# ---- targets ------------------------------------------------------------------------------------------------------
running_source() {  # source hash of the image a service runs; images from before release.sh fall back to "adopt"
  local h; h="$(label_of "${REPO[${IMAGE_OF[$1]}]}:$(current_tag "${VAR_OF[$1]}" "$1")" sentinel.source)"
  [ -n "$h" ] || h="$(cat "$STATE/adopted.${VAR_OF[$1]}" 2>/dev/null || true)"
  echo "$h"
}
changed_targets() {
  local out=() h svc
  h="$(source_hash backend)"
  for svc in "${BACKEND_SERVICES[@]}"; do [ "$(running_source "$svc")" = "$h" ] || out+=("$svc"); done
  [ "$(running_source ansible)" = "$(source_hash ansible)" ] || out+=(ansible)
  h="$(source_hash web)"
  local ui_src; ui_src="$(label_of "fortisiem-web:$(env_get UI_TAG)" sentinel.source)"
  [ "$ui_src" = "$h" ] || out+=(ui)
  [ "$(label_of "fortisiem-web:$(current_tag WEB_TAG edge)" sentinel.edge)" = "$(edge_hash)" ] || out+=(edge)
  [ "$(running_source ingress)" = "$(source_hash ingress)" ] || out+=(ingress)
  if grep -qE '^COMPOSE_PROFILES=.*tacacs' .env; then [ "$(running_source tacacs)" = "$(source_hash tacacs)" ] || out+=(tacacs); fi
  echo "${out[@]:-}"
}

expand() {  # targets → ordered service list
  local want=() t
  for t in "$@"; do
    case "$t" in
      backend) want+=("${BACKEND_SERVICES[@]}");;
      all) want+=("${BACKEND_SERVICES[@]}" ansible ui); for t in $(changed_targets); do case "$t" in edge|ingress|tacacs) want+=("$t");; esac; done;;
      auto) read -r -a t <<<"$(changed_targets)"; want+=("${t[@]}");;
      migrate|api|poller|worker|access|syslog|traps|flows|ansible|ui|edge|ingress|tacacs) want+=("$t");;
      *) die "unknown target: $t";;
    esac
  done
  # one deployment per service, in dependency order: schema first, the api before what calls it, the proxy last
  local order=(migrate api poller worker access syslog traps flows ansible ui edge ingress tacacs) o w
  for o in "${order[@]}"; do for w in "${want[@]:-}"; do [ "$w" = "$o" ] && { echo "$o"; break; }; done; done
}

write_status() {
  local svc first=1 c st h n
  {
    printf '{"ts":"%s","ui_release":"%s","services":{' "$(now)" "$(safe "$(env_get UI_TAG)")"
    for svc in api worker poller access syslog traps flows ansible edge ingress tacacs postgres clickhouse; do
      local cs; cs="$(svc_of "$svc")"
      n=0; st=""; h=""
      for c in $(ids "$cs"); do n=$((n + 1)); read -r st h <<<"$(cstate "$c")"; done
      [ "$n" = 0 ] && [ "$svc" = tacacs ] && continue
      [ $first = 1 ] || printf ','; first=0
      printf '"%s":{"tag_var":"%s","tag":"%s","state":"%s","health":"%s","containers":%d}' "$svc" "${VAR_OF[$svc]:-}" \
        "$(safe "$(current_tag "${VAR_OF[$svc]:-X_TAG}" "$svc" 2>/dev/null || true)")" "${st:-absent}" "${h:-}" "$n"
    done
    printf '}}\n'
  } > "$STATE/status.json.tmp" && mv "$STATE/status.json.tmp" "$STATE/status.json"
}

prune_images() {  # keep the images in use and the newest KEEP_IMAGES of each repository (rollback without rebuilding)
  local img repo inuse t
  inuse="$(grep -E '^[A-Z]+_TAG=' .env | cut -d= -f2 | sort -u)"
  for img in backend web ansible; do
    repo="${REPO[$img]}"
    docker images "$repo" --format '{{.Tag}}' | grep -v '<none>' | tail -n +"$((KEEP_IMAGES + 1))" | while read -r t; do
      grep -qx "$t" <<<"$inuse" || docker rmi "$repo:$t" >/dev/null 2>&1 || true
    done
  done
}

cmd_deploy() {
  local targets=() a
  for a in "$@"; do case "$a" in --no-cache) NO_CACHE=--no-cache;; --allow-destructive) ALLOW_DESTRUCTIVE=--allow-destructive;; --force) FORCE=1;;
                                 *) targets+=("$a");; esac; done
  [ ${#targets[@]} -gt 0 ] || targets=(auto)
  mapfile -t services < <(expand "${targets[@]}")
  if [ ${#services[@]} -eq 0 ] || [ -z "${services[0]}" ]; then log "nothing changed: no deployment needed"; write_status; return 0; fi
  log "deploying: ${services[*]}"
  declare -A built=()
  local svc img tag t0=$(date +%s)
  # build everything first: a failing build stops here, before any running service is touched
  for svc in "${services[@]}"; do img="${IMAGE_OF[$svc]}"; [ -n "${built[$img]:-}" ] || built[$img]="$(build "$img")"; done
  # backend schema before backend services (expand-only migrations: the old version keeps working on the new schema)
  if [ -n "${built[backend]:-}" ] && ! printf '%s\n' "${services[@]}" | grep -qx migrate && [ "$(current_tag MIGRATE_TAG migrate)" != "${built[backend]}" ]; then
    services=(migrate "${services[@]}")
  fi
  for svc in "${services[@]}"; do
    tag="${built[${IMAGE_OF[$svc]}]}"
    case "${STRATEGY[$svc]}" in
      migrate) deploy_migrate "$tag";;
      rolling) deploy_rolling "$svc" "$tag";;
      recreate) deploy_recreate "$svc" "$tag";;
      ui) deploy_ui "$tag";;
      edge) deploy_edge "$tag";;
    esac
  done
  [ -z "${built[backend]:-}" ] || set_tag BACKEND_TAG "${built[backend]}"
  write_status
  prune_images
  log "done in $(( $(date +%s) - t0 )) s: ${services[*]}"
}

cmd_rollback() {
  local svc="${1:-}"; [ -n "$svc" ] || die "usage: release.sh rollback <service>"
  [ -n "${VAR_OF[$svc]:-}" ] || die "unknown service: $svc"
  local var="${VAR_OF[$svc]}" cur prev
  cur="$(current_tag "$var" "$svc")"
  prev="$(grep -E "^$var=" "$STATE/versions.prev.env" 2>/dev/null | cut -d= -f2- || true)"
  [ -n "$prev" ] || die "$svc: no previous version recorded"
  if [ "$svc" != ui ]; then docker image inspect "${REPO[${IMAGE_OF[$svc]}]}:$prev" >/dev/null 2>&1 || die "$svc: image $prev is no longer on the server"; fi
  log "rollback $svc: $cur → $prev (no rebuild; database migrations are not reversed)"
  FORCE=1
  case "${STRATEGY[$svc]}" in
    rolling) deploy_rolling "$svc" "$prev";;
    recreate) deploy_recreate "$svc" "$prev";;
    edge) deploy_recreate edge "$prev";;
    ui) UI_TAG="$cur" dc run --rm --no-deps -T ui-release --switch "$prev" && set_tag UI_TAG "$prev" && record ui "$cur" "$prev" ok 0 "rollback: switched";;
    migrate) die "migrations are not rolled back automatically (expand-only: the previous version runs on the new schema)";;
  esac
  sed -i "s/\"service\":\"$svc\",\"from\":\"$cur\",\"to\":\"$prev\",\"result\":\"ok\"/\"service\":\"$svc\",\"from\":\"$cur\",\"to\":\"$prev\",\"result\":\"ok\",\"kind\":\"rollback\"/" "$HIST" || true
  write_status
}

cmd_status() {
  write_status
  printf '%-10s %-26s %-26s %s\n' SERVICE TAG PREVIOUS STATE
  local svc var
  for svc in api worker poller access syslog traps flows ansible migrate ui edge ingress tacacs; do
    var="${VAR_OF[$svc]}"
    printf '%-10s %-26s %-26s %s\n' "$svc" "$(current_tag "$var" "$svc")" "$(grep -E "^$var=" "$STATE/versions.prev.env" 2>/dev/null | cut -d= -f2- || true)" \
      "$(for c in $(ids "$(svc_of "$svc")"); do cstate "$c"; done | sort | uniq -c | xargs)"
  done
  echo "changed since build: $(changed_targets)"
}

FORCE=""
case "${1:-}" in
  deploy) shift; cmd_deploy "$@";;
  rollback) shift; cmd_rollback "$@";;
  status) cmd_status;;
  history) tail -n "${2:-20}" "$HIST" 2>/dev/null || true;;
  adopt) shift   # record that services running an image built before release.sh match the current source (no restart)
    for svc in "$@"; do [ -n "${VAR_OF[$svc]:-}" ] || die "unknown service: $svc"
      source_hash "${IMAGE_OF[$svc]}" > "$STATE/adopted.${VAR_OF[$svc]}"; log "adopted $svc as source $(cat "$STATE/adopted.${VAR_OF[$svc]}")"; done;;
  build) shift; for a in "$@"; do [ "$a" = --no-cache ] && NO_CACHE=--no-cache; done; build "$1";;
  *) sed -n '2,28p' "$0"; exit 2;;
esac
