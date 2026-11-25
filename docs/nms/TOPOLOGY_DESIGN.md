# Topology design

Implementation: `backend/app/switches/topology.py`. UI: `frontend/src/pages/switches/Topology.tsx` (echarts graph with
search, zoom, pan, filters, node drill-down and the impact panel).

## Sources and what they prove

| Source | Collected by | Gives | Observed / inferred |
|---|---|---|---|
| LLDP (LLDP-MIB remote table) | `collect_neighbors` | Local port ↔ remote chassis / port / system name | **Observed** link |
| CDP (CISCO-CDP-MIB) | `collect_neighbors` | Local port ↔ remote device / port / platform / address | **Observed** link |
| Controller CDP data for APs (9800) | wireless collector | AP ↔ switch port (`protocols: ["cdp (controller)"]`) | **Observed** (reported by the controller) |
| Firewall registry | `topology.build` | Switch ↔ firewall when the neighbour matches a registered firewall | Observed link, matched to the firewall inventory |
| Configured parents (`switches.parent_id`) | administrators | Dependency chain for alert suppression and impact | **Configured** |
| Parent suggestions | `infer_parents()` | Upstream device by role (core > distribution > access) and hop distance from a root | **Inferred**; shown as "(inferred)" and applied only when an administrator accepts |

- **Edge fields:** every edge carries the protocols that reported it (`lldp`, `cdp`, `cdp (controller)`) and
  `bidirectional` (seen from both ends).
- **Link status:**

  | Status | Meaning |
  |---|---|
  | `up` | Link reported and healthy |
  | `degraded` | ≥ 80 % utilisation, or errors on either end |
  | `down` | Oper status down |
  | `lost` | The neighbour disappeared within the last hours; drawn red dashed |
  | `unknown` | The local port is not mapped |

  Observed links come only from what devices report. Inferred relationships exist only as parent suggestions, never as
  drawn links. The MAC address table (Bridge / Q-BRIDGE) is collected for the MAC search and port views; it is not used
  to draw links.

## Features

- **Interface mapping:** interface-to-interface links. A link on a port-channel member carries the LAG's ifIndex
  (`lag_ifindex`).
- **Health on the graph:**
  - node state from polling (up / down / auth failed / unknown);
  - link status as above, with the highest utilisation of the two ends.
- **Impact:** the "if this fails" panel from `impact(sid)` (BFS down the configured parents, filled with suggested
  parents where none is configured) shows downstream switches, APs, current clients and SSIDs. The root's
  `switch_unreachable` alert carries the same figures.
- **Unknown devices:** neighbours not matched to the inventory are shown as `external` nodes with their LLDP / CDP
  identity. The summary also counts switches that report no neighbours at all.
- **Duplicates:** a cable seen from both ends is merged into one link, and each end fills in its own interface.
- **Corrections:**
  - administrators set or accept parents in Device Dependencies, and configured parents always win over suggestions;
  - a wrong neighbour entry is fixed on the device (LLDP / CDP configuration).
- **Refresh:** neighbours are re-read with each poll's neighbour group; the page rebuilds the graph on load and on
  refresh.

## Not built

| Item | Note |
|---|---|
| Layer-3 topology from routing tables / ARP | No `ipNetToMedia` / route-table walk. BGP / OSPF peers are shown on the BGP pages, not as graph edges. |
| WAN / site-to-site graph | WAN circuits and VPN tunnels are monitored (docs/WAN.md, VPN tunnels) but not drawn as a topology layer |
| LLDP-V2-MIB-only devices | Not read |
| Manual edges | Links cannot be drawn by hand (only parents can be set) |
| MAC-table placement | Hosts are not placed on the graph from the bridge tables |
