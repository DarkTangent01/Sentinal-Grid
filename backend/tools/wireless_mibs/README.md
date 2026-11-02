# Wireless OID registry generator

`app/wireless/oids.py` is generated from Cisco's published MIB sources, not written by hand.

    mkdir mibs && for m in CISCO-SMI CISCO-LWAPP-TC-MIB CISCO-LWAPP-AP-MIB CISCO-LWAPP-WLAN-MIB CISCO-LWAPP-DOT11-CLIENT-MIB \
        CISCO-LWAPP-DOT11-MIB CISCO-LWAPP-RF-MIB CISCO-LWAPP-CLIENT-ROAMING-MIB CISCO-LWAPP-CDP-MIB AIRESPACE-REF-MIB AIRESPACE-WIRELESS-MIB; do
      curl -sfL -o mibs/$m.my https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/$m.my; done
    python3 -I mibres.py mibs oids.json          # resolve every OBJECT-TYPE to its numeric OID
    python3 -I enums.py mibs enums.json         # INDEX clauses and INTEGER enumerations of the selected objects
    python3 -I gen_registry.py oids.json enums.json > ../../app/wireless/oids.py

The generator refuses objects that are not readable (MAX-ACCESS read-only / read-write / read-create). Device support is
decided per controller at run time by the capability registry.
