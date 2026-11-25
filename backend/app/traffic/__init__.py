"""Sentinel NMS — Application & Protocol Intelligence (docs/nms/TRAFFIC_INTELLIGENCE.md).

Turns the flow records collected by app/flows (NetFlow v5 / v9, IPFIX, sFlow v5) into application, protocol,
conversation, VLAN and interface analytics with evidence-based classification, and raises traffic detections through
the NMS alert framework.

  registry   signature registry (port / ASN / domain) seeded into PostgreSQL, compiled to ClickHouse lookups
  networks   administrator-defined ranges: internal / external, site, VLAN, zone; direction classification
  settings   deduplication, LAG handling, authorised services, enrichment switches
  query      filter model, table selection (raw records or hourly rollups) and SQL building
  analytics  the read models behind the API
  enrich     asynchronous enrichment (DNS logs, firewall application control, ASN, optional reverse DNS) and host lookup
  detections traffic security rules registered with the alert framework
"""
