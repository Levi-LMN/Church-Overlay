from datetime import datetime, timedelta
from functools import wraps

from flask import make_response, redirect, request, url_for, jsonify
from flask_login import current_user

from extensions import db, overlay_state, state_lock


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def auth_required():
    """Return True if the app is configured to require login."""
    from models import Settings
    try:
        setting = Settings.query.filter_by(key='require_auth').first()
        return setting and setting.value == 'true'
    except Exception:
        return False


def admin_required(f):
    """Decorator: endpoint requires an authenticated admin user."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if not current_user.is_admin:
            log_activity('UNAUTHORIZED_ACCESS_ATTEMPT',
                         f'Attempted admin access: {request.path}')
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


def login_optional(f):
    """Decorator: redirect to login only when auth is required globally."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if auth_required() and not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def no_cache(view):
    """Decorator: attach aggressive no-cache headers to a response."""
    @wraps(view)
    def no_cache_view(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = (
            'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        )
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Vary'] = '*'
        return response
    return no_cache_view


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log_activity(action, details=None):
    """Persist an activity log entry."""
    from models import ActivityLog
    try:
        log = ActivityLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            user_email=current_user.email if current_user.is_authenticated else 'Anonymous',
            user_name=current_user.name if current_user.is_authenticated else 'Anonymous',
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error logging activity: {e}")


def cleanup_old_logs():
    """Delete activity logs older than 7 days."""
    from models import ActivityLog
    try:
        cutoff = datetime.utcnow() - timedelta(days=7)
        deleted = ActivityLog.query.filter(ActivityLog.timestamp < cutoff).delete()
        if deleted:
            db.session.commit()
            print(f"[CLEANUP] Removed {deleted} old activity logs")
    except Exception as e:
        db.session.rollback()
        print(f"Error cleaning up logs: {e}")


def cleanup_temporary_content():
    """Delete temporary content older than 1 day."""
    from models import TemporaryContent
    try:
        cutoff = datetime.utcnow() - timedelta(days=1)
        deleted = TemporaryContent.query.filter(TemporaryContent.created_at < cutoff).delete()
        if deleted:
            db.session.commit()
            print(f"[CLEANUP] Removed {deleted} temporary content items")
    except Exception as e:
        db.session.rollback()
        print(f"Error cleaning up temporary content: {e}")


# ---------------------------------------------------------------------------
# SSE / state
# ---------------------------------------------------------------------------

def notify_state_change():
    """Bump overlay version so polling clients detect the change."""
    import time
    with state_lock:
        overlay_state['version'] += 1
        overlay_state['timestamp'] = time.time()