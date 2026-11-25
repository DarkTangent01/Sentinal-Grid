"""Sentinel NMS Device Access Gateway: browser SSH terminal, connectivity tests, diagnostics, bulk diagnostics,
approved configuration changes, credential vault and the access audit. See docs/nms/DEVICE_ACCESS_ARCHITECTURE.md.

Every device connection made here goes through gateway.resolve(): the device must be in the inventory and in the user's
site scope, its management address must pass the management-network allowlist, and the port comes from a fixed
protocol map. No API accepts a host, a port or a free-text command for a device.
"""
