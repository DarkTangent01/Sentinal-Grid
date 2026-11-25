"""Business-free building blocks shared by Sentinel Grid (SIEM) and Sentinel NMS (docs/architecture/SHARED_COMPONENTS.md).

Rules (enforced by tests/test_product_boundaries.py): nothing in here imports a product module; product modules may
import from here. Nothing in here holds product data or product-specific behaviour.
"""
