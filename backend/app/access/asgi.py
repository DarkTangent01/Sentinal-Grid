"""ASGI entry point of the Device Access Gateway service (uvicorn app.access.asgi:app)."""
from ..main import create_app

app = create_app("access")
