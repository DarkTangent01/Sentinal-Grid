"""Device Access Gateway service: python -m app.access. One process: terminal sessions live in its memory, and the
session caps are counted in the database."""
import uvicorn


def main() -> None:
    uvicorn.run("app.access.asgi:app", host="0.0.0.0", port=8100, workers=1, server_header=False, ws_max_size=1 << 20, log_config=None)


if __name__ == "__main__":
    main()
