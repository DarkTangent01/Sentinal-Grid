#!/bin/sh
# Prepare the shared volumes (config: written by the SIEM worker, read by the agent; logs: written by tac_plus-ng, read
# by the SIEM worker), then run the agent unprivileged. The agent supervises tac_plus-ng.
set -eu
for d in /tacacs/config /tacacs/config/requests /tacacs/config/candidates /tacacs/config/results /tacacs/config/active \
         /tacacs/config/backups /tacacs/logs; do
  mkdir -p "$d"
done
chown -R tacacs:tacshare /tacacs/config /tacacs/logs
chmod 2770 /tacacs/config /tacacs/config/requests /tacacs/config/candidates /tacacs/config/results /tacacs/logs
chmod 2750 /tacacs/config/active /tacacs/config/backups
ACTIVE=/tacacs/config/active/tac_plus-ng.cfg
# deny-all bootstrap configuration: listens on 49, knows no devices, logs to the shared volume. Installed when there is no
# active configuration, and refreshed when the active one is still an (older) bootstrap; a SIEM-deployed version is never touched.
if [ ! -s "$ACTIVE" ] || { head -n 2 "$ACTIVE" | grep -q '^# Bootstrap configuration installed on first start' && ! cmp -s /opt/tacagent/bootstrap.cfg "$ACTIVE"; }; then
  install -o tacacs -g tacshare -m 0640 /opt/tacagent/bootstrap.cfg "$ACTIVE"
fi
umask 0007
exec setpriv --reuid=tacacs --regid=tacshare --init-groups --inh-caps=-all python3 /opt/tacagent/agent.py
