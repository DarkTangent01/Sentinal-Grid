# Sentinel NMS extensions

This release adds discovery, layer-3 / WAN topology, NETCONF / RESTCONF, Telnet, serial console, wireless integrations
and Ansible.

Everything here is tested against simulators (asyncssh / asyncio servers on loopback, httpx mock transports shaped after
each vendor's documented API responses, and a real ansible-core 2.18.9 run against a simulated IOS device). Nothing is
validated against real hardware, a controller or a cloud tenant.

Tests: `backend/tests/test_nms_extensions.py` (29). To run the real-Ansible test, set `ANSIBLE_TEST_BIN` and
`ANSIBLE_COLLECTIONS_PATH`.

## 1. Discovery: ICMP, TCP, ARP (`app/switches/discovery.py`)

| Method | What it does |
|---|---|
| `snmp` | One GET of sysDescr / sysObjectID / sysName. Needs an SNMP credential profile. |
| `icmp` | One echo per address, 800 ms |
| `tcp` | Connects to 22, 23, 80, 443 and 830 (800 ms each) and reports the services it found |
| `arp` | Walks ipNetToMediaPhysAddress on the monitored devices that are up (in authorised networks only) and keeps entries inside the network being discovered. Silent hosts appear with their MAC address and the device that learned them. |

- **Scope:** runs only in an authorised network with "allow discovery" set. Addresses go through netguard (no loopback
  or reserved addresses).
- **Limits:** the subnet-size cap and the bounded concurrency still apply.
- **Onboarding:** nothing is added automatically.
- **UI:** Switch Monitoring → Settings → Discovery has a method checkbox for each method. The credential is needed only
  for SNMP. Results show the methods that answered, the services, and the MAC with the device that learned it.
- **API:** `POST /api/switches/admin/discovery {network_id, methods, credential_id?}`.

## 2. Layer-3 and WAN topology (`app/switches/l3topology.py`)

| Edge | Source | State |
|---|---|---|
| `ospf` | OSPF-MIB neighbour table of polled devices | `full` → up |
| `bgp` | BGP4-MIB peers of polled devices; FortiGate BGP API | established → up |
| `ipsec` | FortiGate VPN logs (last 24 h) | tunnel status |
| `isp` | Circuit inventory (`isp_links`) | down while a WAN outage is open |

- **Far-end matching:** a far end is matched to inventory by management address, by IP-MIB interface address, or by
  a firewall or BGP local address. Otherwise it is an external node (AS, VPN peer, OSPF router).
- **Edge record:** every edge records its `source` and `matched_by`.
- **Duplicates:** an adjacency reported from both ends is one edge.
- **UI:** Switch Monitoring → Topology → "Layer 3 & WAN", with per-protocol filters, a graph and a link table.
  Circuits are drawn dotted.
- **API:** `GET /api/switches/topology/l3?site=`.

## 3. NETCONF and RESTCONF read operations (`app/access/netconf.py`)

- **Operations:** a fixed catalogue only.

  | Protocol | Operations |
  |---|---|
  | NETCONF | capabilities, running configuration (masked), ietf-interfaces state, YANG library, Junos interfaces / chassis / BGP |
  | RESTCONF | YANG library, ietf-interfaces (config and state), IOS-XE version / hostname, OpenConfig interfaces |

  Every NETCONF RPC is checked at import to be a read (`get`, `get-config`, `get-*-information`).
- **NETCONF connection:**
  - TCP 830 to the inventory address, through the gateway's single dial function (pinned SSH host key);
  - netconf credential, else the ssh credential;
  - base:1.0 framing.
- **RESTCONF connection:**
  - HTTPS 443, with the https credential, else the ssh credential;
  - the device certificate's SHA-256 is pinned on first use (`switches.https_cert_sha256`);
  - an unauthenticated request checks the certificate before credentials are sent;
  - a changed certificate is refused until an administrator resets the pin
    (`POST /api/nms/access/devices/{id}/https-cert/accept`).
- **Output:** secrets in replies (XML and JSON) are masked. Results are stored as diagnostic jobs and the run is
  audited.
- **UI:** device → Access → "NETCONF / RESTCONF".

## 4. Telnet (`app/access/telnet.py`, `channels.py`)

- **Off by default:** Telnet needs `ACCESS_TELNET_ENABLED=true` and the per-device switch "allow Telnet for this
  device" (administrators). The device button warns that Telnet is clear text before connecting.
- **Login:** the gateway answers the Username and Password prompts with the vault credential; the browser never sees
  it.
- **Same rules as SSH:** the same line guard (read-only unless an approved change), recording, timeouts and
  termination.
- **Marking:** the audit and the session are marked `cleartext`.
- **Option negotiation:** accept ECHO and SGA, offer NAWS (window size), refuse everything else.

## 5. Serial console (`app/access/channels.py`)

- **Console servers:** Device Access → Console servers (`nms_console_servers`, `nms_console_ports`). Each server has a
  management IP inside an authorised network, a kind, a method and a vault ssh credential. Each port is mapped to an
  inventory device.

  | Kind / method | Connection |
  |---|---|
  | Opengear SSH | `ssh <user>:portNN@server` |
  | Cisco terminal server SSH | `ssh -l <user>:<line> server` |
  | Telnet (either kind) | `server` port 2000 + port, clear text; needs `ACCESS_TELNET_ENABLED` |

- **Host key:** the console server's SSH host key is pinned on first use. An administrator can reset it.
- **Sessions:** a console session is opened from the mapped device's Access tab. It uses the device's RBAC and site
  scope, the same guard and the same audit (protocol `console`).
- **Device login:** answers to the device's own login prompt are recorded as `<login name>`; passwords are never
  recorded.

## 6. Wireless controller and cloud integrations (`app/wireless/integrations.py`)

| Kind | API used (read-only) | Credential (vault) | Allowed host |
|---|---|---|---|
| Ruckus SmartZone / vSZ | Public API: serviceTicket, `query/ap`, `query/client` | https (user / password) | IP inside an authorised network, port 8443 / 7443 / 443 |
| Ruckus One | OAuth2 client credentials, `/venues/aps/query`, `/venues/aps/clients/query` | api_token (username = client id, token = secret) | `*.ruckus.cloud` |
| Juniper Mist | Token auth, `/orgs/{org}/sites`, `/sites/{site}/stats/devices`, `/stats/clients` | api_token | `*.mist.com` |
| Aruba Central | Bearer token, `/monitoring/v2/aps`, `/monitoring/v1/clients/wireless`; refresh on 401 | api_token (+ client id / secret / refresh token) | `*.central.arubanetworks.com` |

- **Pipeline:** the normalised APs, radios, WLANs and clients go through the same persistence as the 9800 SNMP
  collector. History, sessions, roaming, floors, analytics, events and alerts therefore work unchanged.
- **Virtual controller:** data is stored under a virtual controller row (`address integration:<kind>:<id>`,
  `monitoring external`). It is never SNMP-polled or backed up, and the access gateway refuses it.
- **Offline APs:** an AP the vendor reports offline is treated as missing from the AP table, and goes down after the
  usual number of missed polls.
- **Aruba tokens:** a rotated Aruba refresh token is stored back, encrypted.
- **Schedule:** the worker loop `wireless_integrations` syncs every integration on its own interval (default 300 s).
  A lease stops two workers from syncing the same one.
- **UI:** Wireless → Integrations (administrators manage, everyone sees status), with "Sync now".
- **API:** `/api/wireless/integrations`.
- **Validation:** request paths and field names follow each vendor's published API. Confirm the first sync against
  your own tenant or controller, and check the AP and client counts.

## 7. Ansible automation (`app/playbooks/`, service `ansible`)

- **Runner image:** `backend/Dockerfile.ansible`. Python environment of the backend, plus:
  - `ansible-core 2.18.9` and `paramiko 3.5.1`;
  - collections `ansible.netcommon 8.7.1`, `ansible.utils 6.1.1`, `cisco.ios 11.6.0`, `cisco.nxos 13.0.0`,
    `junipernetworks.junos 11.1.1`, `juniper.device 2.0.7`, `arista.eos 12.3.0`.

  About 100 MB on top of the backend packages (measured locally). Only this image has Ansible.
- **Policy** (`policy.py`, static, on the stored text):
  - **read-only:** facts / command modules (ios, nxos, junos, eos, `netcommon.cli_command`) with literal commands that
    classify `READ_ONLY` / `LOW_RISK`, plus debug / set_fact / assert / fail;
  - **change:** network configuration modules (`*_config`, resource modules, `netcommon.cli_config`), with no `src`
    and no destructive lines;
  - **refused:**
    - shell, command, raw, script, copy, template, file and uri modules, and any other module not on the lists;
    - delegate_to, local_action and blocks;
    - roles, includes, imports and vars_files;
    - lookup, query and env Jinja;
    - become methods other than enable;
    - hosts other than `targets`.
- **Library:**
  - writing needs `nms.automation.execute`;
  - each saved version is checked and starts as a draft;
  - approval needs `nms.configuration.approve`, and the approver cannot be the last editor;
  - editing clears the approval.
- **Runs:**
  - read-only playbooks, and dry runs (`--check --diff`) of change playbooks, are queued directly;
  - a real change run needs `nms.device.access.configuration`, `NMS_CONFIG_CHANGES_ENABLED`, and a second person's
    approval of that run.
- **Runner:**
  - runs one run at a time;
  - re-checks the approved SHA-256 and the policy;
  - builds a private 0700 work directory with a 0600 inventory of only the run's devices (validated address, network
    OS, vault credential);
  - writes `known_hosts` with Sentinel's pinned keys; devices without a pinned key are skipped;
  - keeps host key checking on with auto-add off, and starts the process with a minimal environment;
  - enforces a hard timeout and supports cancellation;
  - backs up before and after a change run, refusing to run if a before-backup fails, and stores the diffs;
  - masks the output (including echoed passwords);
  - deletes the work directory and audits the run.
- **UI:** Device Access → Automation (Ansible): playbooks, policy check, approval, run dialog, run output.
- **Lab results:**
  - a read-only `cisco.ios.ios_command` playbook ran through the runner against the simulated device: `ok=2`, with the
    device output;
  - after the simulator's key changed, the run was refused with "host key mismatch", as intended;
  - a `shell` playbook was refused by the policy.

## Settings

```
ACCESS_TELNET_ENABLED=false          # Telnet to devices / console servers (also per device / per console server)
RESTCONF_TIMEOUT_SECONDS=30
ANSIBLE_PLAYBOOK_BIN=ansible-playbook  ANSIBLE_RUN_TIMEOUT_SECONDS=1800  ANSIBLE_FORKS=10  ANSIBLE_MAX_DEVICES=200
WIRELESS_INTEGRATION_TIMEOUT_SECONDS=30  WIRELESS_INTEGRATION_MAX_CLIENTS=50000
```

## Migration

PostgreSQL **0036**, additive (tested up / down / up):
- `switches.https_cert_sha256`, `switches.access_telnet`;
- `switch_discovery_runs.methods`, and `credential_id` made nullable;
- `nms_access_sessions.console_port_id`;
- tables `nms_console_servers`, `nms_console_ports`, `wireless_integrations`, `nms_playbooks`, `nms_playbook_runs`.

## Lab finding (not a product defect)

Running the Ansible runner inside the same process as the embedded ClickHouse (chdb, used only in development) froze
that process: chdb's signal handler blocked the event loop. In production the runner is its own container and never
loads chdb. The lab now runs it as a separate process too.
