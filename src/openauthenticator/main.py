from uvicorn import run
from openauthenticator.api import app

if __name__ == "__main__":
    run(app, host="0.0.0.0", port=8000)
