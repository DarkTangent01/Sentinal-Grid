# Bundled reference data

- `manuf.gz` — MAC address block → manufacturer, from Wireshark's generated list
  (https://www.wireshark.org/download/automated/data/manuf.gz, built with `tshark -G manuf` from the IEEE
  registration authority's public MA-L / MA-M / MA-S registries). Downloaded 2026-11-25 (file dated 2026-11-24).
  Refresh by downloading the same file (at most weekly, as its header asks) and replacing this one.
