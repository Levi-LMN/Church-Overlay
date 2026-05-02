from datetime import datetime

from flask_login import UserMixin

from extensions import db  # single shared SQLAlchemy instance


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(500))


class Church(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500))
    accent_color = db.Column(db.String(20), default='#10b981')
    church_label_color = db.Column(db.String(20), default='#10b981')
    main_title_color = db.Column(db.String(20), default='#ffffff')
    subtitle_color = db.Column(db.String(20), default='rgba(255, 255, 255, 0.85)')
    verse_color = db.Column(db.String(20), default='#10b981')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Minister(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    title = db.Column(db.String(200))
    last_used = db.Column(db.DateTime)


class Sermon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    minister_name = db.Column(db.String(200))
    bible_verse = db.Column(db.String(500))
    date = db.Column(db.DateTime, default=datetime.utcnow)


class TemporaryContent(db.Model):
    """Temporary custom ministers and sermons (auto-deleted after 1 day)."""
    id = db.Column(db.Integer, primary_key=True)
    content_type = db.Column(db.String(20), nullable=False)   # 'minister' | 'sermon'
    name = db.Column(db.String(200))
    title = db.Column(db.String(300))
    minister_name = db.Column(db.String(200))
    bible_verse = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    last_used = db.Column(db.DateTime)


class AnimationSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # ── Rotation ──────────────────────────────────────────────────────────
    auto_rotate         = db.Column(db.Boolean, default=True)
    rotation_interval   = db.Column(db.Integer, default=8)   # seconds between animation changes
    enabled_animations  = db.Column(db.String(500),
                                    default='slide-up,fade-in,slide-left,zoom-in,wave-in')

    # ── Timing ────────────────────────────────────────────────────────────
    animation_speed     = db.Column(db.Float, default=1.0)   # multiplier: 0.5=2× faster, 2.0=2× slower
    typewriter_speed    = db.Column(db.Integer, default=50)  # ms per character

    # ── Auto show / hide cycle ────────────────────────────────────────────
    # When enabled the display page independently hides after display_duration,
    # waits hide_duration, then re-shows — regardless of server state (as long
    # as server mode != 'hidden').
    auto_cycle              = db.Column(db.Boolean, default=False)
    display_duration        = db.Column(db.Integer, default=30)   # seconds visible
    hide_duration           = db.Column(db.Integer, default=10)   # seconds hidden
    cycle_enter_animation   = db.Column(db.String(50), default='auto')   # 'auto' = use pool
    cycle_exit_animation    = db.Column(db.String(50), default='fade-out-exit')


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user_email = db.Column(db.String(120))
    user_name = db.Column(db.String(120))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))

    def to_dict(self):
        return {
            'id': self.id,
            'user_email': self.user_email,
            'user_name': self.user_name,
            'action': self.action,
            'details': self.details,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'ip_address': self.ip_address
        }