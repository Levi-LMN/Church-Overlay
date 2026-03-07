"""
extensions.py — Single source of truth for all shared Flask extension instances.

WHY THIS FILE EXISTS:
  When running `python app.py`, Python registers that module as `__main__`.
  If any blueprint then does `from app import oauth`, Python re-imports app.py
  as a *second*, separate module — creating brand-new, uninitialised instances.
  By moving every singleton here, both app.py and every blueprint always import
  from the same stable module.
"""

import threading
import time

from authlib.integrations.flask_client import OAuth
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

# ---------------------------------------------------------------------------
# Flask extension singletons
# ---------------------------------------------------------------------------
db            = SQLAlchemy()
login_manager = LoginManager()
oauth         = OAuth()
csrf          = CSRFProtect()

# ---------------------------------------------------------------------------
# Global overlay state
# ---------------------------------------------------------------------------
ADMIN_EMAIL = 'mukuhalevi@gmail.com'

overlay_state = {
    'mode': 'hidden',
    'minister': None,
    'sermon': None,
    'church': None,
    'animation': 'slide-up',
    'animation_settings': {},
    'colors': {},
    'version': 0,
    'timestamp': time.time()
}

state_lock = threading.Lock()
state_update_queues: list = []