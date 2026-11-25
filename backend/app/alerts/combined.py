"""Both products' alert rules in one process: today's single deployment, the dev server and the test suite.

A separated product imports only its own registration (alerts.siem or alerts.nms). Here one pass keeps the original
behaviour: every alert of the pass goes through the SIEM after-run step (security incident correlation,
notifications, automation), as before the product split.
"""
from . import engine, nms, siem  # noqa: F401  (registration)

engine.COMBINED_AFTER_RUN = siem.after_run
# asset criticality (a SIEM inventory) keeps raising NMS alert severity in the combined deployment
engine.PRODUCTS["nms"].severity_context = siem._asset_context
