"""Entry point: ``python app.py`` starts the local server on 127.0.0.1."""
import atexit

from config import Config
from fim import create_app

app = create_app()


def _shutdown() -> None:
    worker = app.extensions.get("fim_worker")
    if worker is not None:
        worker.stop()


atexit.register(_shutdown)

if __name__ == "__main__":
    # Debug mode and the reloader are intentionally off: the reloader would start
    # a second process (and a second monitoring worker).
    app.run(host=Config.HOST, port=Config.PORT, debug=False, use_reloader=False)
