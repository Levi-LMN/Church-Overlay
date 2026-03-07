"""
run.py  —  Start the development server.

Always run the app with:
    python run.py
or for production:
    gunicorn "run:app"

Do NOT run `python app.py` directly — that loads app.py as __main__ which
causes a second import of app.py when blueprints do `from app import …`,
creating duplicate, uninitialised extension instances.
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)