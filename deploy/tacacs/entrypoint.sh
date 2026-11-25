#!/bin/sh
# Prepare the shared volumes (config: written by the SIEM worker, read by the agent; logs: written by tac_plus-ng, read
# by the SIEM worker), then run the agent. The agent supervises tac_plus-ng.
#
# Normal start (docker-compose.yml, Kubernetes): already the unprivileged tacacs user (uid 10003, group tacshare), no
# capabilities; the volumes are owned by tacacs:tacshare (image directories, or a previous start). Legacy start as
# root: re-own the volumes, then drop to tacacs as before.
set -eu
for d in /tacacs/config /tacacs/config/requests /tacacs/config/candidates /tacacs/config/results /tacacs/config/active \
         /tacacs/config/backups /tacacs/logs; do
  mkdir -p "$d"
done
# a file in each volume: Podman re-owns an *empty* named volume to the user of the next container that mounts it (the
# worker), which left tac_plus-ng unable to write its logs; Docker never does, the marker is harmless there
touch /tacacs/logs/.volume /tacacs/config/.volume
if [ "$(id -u)" = "0" ]; then
  chown -R tacacs:tacshare /tacacs/config /tacacs/logs
fi
# setgid keeps new files in tacshare (the SIEM worker also sets the group on every file it writes: app/tacacs/jobs.py
# _share). Best effort: as tacacs this only succeeds on the directories it owns, which is all of them in normal use.
chmod 2770 /tacacs/config /tacacs/config/requests /tacacs/config/candidates /tacacs/config/results /tacacs/logs 2>/dev/null || true
chmod 2750 /tacacs/config/active /tacacs/config/backups 2>/dev/null || true
ACTIVE=/tacacs/config/active/tac_plus-ng.cfg
# deny-all bootstrap configuration: listens on 49, knows no devices, logs to the shared volume. Installed when there is no
# active configuration, and refreshed when the active one is still an (older) bootstrap; a SIEM-deployed version is never touched.
if [ ! -s "$ACTIVE" ] || { head -n 2 "$ACTIVE" | grep -q '^# Bootstrap configuration installed on first start' && ! cmp -s /opt/tacagent/bootstrap.cfg "$ACTIVE"; }; then
  install -m 0640 /opt/tacagent/bootstrap.cfg "$ACTIVE"
  [ "$(id -u)" = "0" ] && chown tacacs:tacshare "$ACTIVE"
fi
umask 0007
if [ "$(id -u)" = "0" ]; then
  exec setpriv --reuid=tacacs --regid=tacshare --init-groups --inh-caps=-all python3 /opt/tacagent/agent.py
fi
exec python3 /opt/tacagent/agent.py
