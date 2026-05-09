import os

from dotenv import load_dotenv
from flask import Flask, redirect, url_for
from flask_login import current_user

from extensions import db, login_manager, oauth, csrf, overlay_state, ADMIN_EMAIL


def _migrate_animation_settings(app):
    """Add new AnimationSettings columns to existing SQLite databases."""
    with app.app_context():
        try:
            from sqlalchemy import text
            with db.engine.connect() as conn:
                rows = conn.execute(text("PRAGMA table_info(animation_settings)")).fetchall()
                existing = {row[1] for row in rows}

                migrations = [
                    ('animation_speed',           'FLOAT DEFAULT 1.0'),
                    ('typewriter_speed',           'INTEGER DEFAULT 50'),
                    ('auto_cycle',                 'BOOLEAN DEFAULT 0'),
                    ('display_duration',           'INTEGER DEFAULT 30'),
                    ('hide_duration',              'INTEGER DEFAULT 10'),
                    ('cycle_enter_animation',      "VARCHAR(50) DEFAULT 'auto'"),
                    ('cycle_exit_animation',       "VARCHAR(50) DEFAULT 'fade-out-exit'"),
                    # Secondary message / ticker columns
                    ('ticker_enabled',             'BOOLEAN DEFAULT 1'),
                    ('ticker_duration',            'INTEGER DEFAULT 6'),
                    ('ticker_delay',               'INTEGER DEFAULT 4'),
                    ('ticker_enter_animation',     "VARCHAR(50) DEFAULT 'fade-in'"),
                    ('ticker_exit_animation',      "VARCHAR(50) DEFAULT 'fade-out-exit'"),
                    ('ticker_end_behavior',        "VARCHAR(20) DEFAULT 'loop'"),
                ]
                for col, defn in migrations:
                    if col not in existing:
                        conn.execute(text(f"ALTER TABLE animation_settings ADD COLUMN {col} {defn}"))
                        print(f"[MIGRATION] Added column: animation_settings.{col}")
                conn.commit()
        except Exception as e:
            print(f"[MIGRATION] {e}")


def _anim_to_dict(anim):
    """Convert an AnimationSettings row to the overlay_state dict format."""
    return {
        'auto_rotate':            anim.auto_rotate,
        'rotation_interval':      anim.rotation_interval,
        'enabled_animations':     anim.enabled_animations.split(','),
        'animation_speed':        anim.animation_speed        if anim.animation_speed        is not None else 1.0,
        'typewriter_speed':       anim.typewriter_speed       if anim.typewriter_speed       is not None else 50,
        'auto_cycle':             anim.auto_cycle             if anim.auto_cycle             is not None else False,
        'display_duration':       anim.display_duration       if anim.display_duration       is not None else 30,
        'hide_duration':          anim.hide_duration          if anim.hide_duration          is not None else 10,
        'cycle_enter_animation':  anim.cycle_enter_animation  if anim.cycle_enter_animation  is not None else 'auto',
        'cycle_exit_animation':   anim.cycle_exit_animation   if anim.cycle_exit_animation   is not None else 'fade-out-exit',
        # Ticker / secondary messages
        'ticker_enabled':         anim.ticker_enabled         if anim.ticker_enabled         is not None else True,
        'ticker_duration':        anim.ticker_duration        if anim.ticker_duration        is not None else 6,
        'ticker_delay':           anim.ticker_delay           if anim.ticker_delay           is not None else 4,
        'ticker_enter_animation': anim.ticker_enter_animation if anim.ticker_enter_animation is not None else 'fade-in',
        'ticker_exit_animation':  anim.ticker_exit_animation  if anim.ticker_exit_animation  is not None else 'fade-out-exit',
        'ticker_end_behavior':    anim.ticker_end_behavior    if anim.ticker_end_behavior    is not None else 'loop',
    }


def create_app():
    load_dotenv()

    app = Flask(__name__)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

    basedir = os.path.abspath(os.path.dirname(__file__))
    instance_path = os.path.join(basedir, 'instance')
    os.makedirs(instance_path, exist_ok=True)

    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', f'sqlite:///{os.path.join(instance_path, "obs_overlay.db")}'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['GOOGLE_CLIENT_ID']     = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

    app.config['WTF_CSRF_CHECK_DEFAULT'] = False

    # ------------------------------------------------------------------
    # Initialise extensions
    # ------------------------------------------------------------------
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    csrf.init_app(app)

    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )

    # ------------------------------------------------------------------
    # User loader
    # ------------------------------------------------------------------
    from models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # ------------------------------------------------------------------
    # Register blueprints
    # ------------------------------------------------------------------
    from blueprints.auth    import auth_bp
    from blueprints.admin   import admin_bp
    from blueprints.user    import user_bp
    from blueprints.display import display_bp
    from blueprints.api     import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp,   url_prefix='/admin')
    app.register_blueprint(user_bp,    url_prefix='/user')
    app.register_blueprint(display_bp, url_prefix='/display')
    app.register_blueprint(api_bp,     url_prefix='/api')

    csrf.exempt(api_bp)

    # ------------------------------------------------------------------
    # Root route
    # ------------------------------------------------------------------
    from utils.helpers import auth_required as check_auth_required

    @app.route('/')
    def index():
        if not current_user.is_authenticated:
            if check_auth_required():
                return redirect(url_for('auth.login'))
            return redirect(url_for('user.panel'))
        if current_user.is_admin:
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('user.panel'))

    # ------------------------------------------------------------------
    # Database bootstrap
    # ------------------------------------------------------------------
    with app.app_context():
        from models import Settings, AnimationSettings, Church, User
        from utils.helpers import cleanup_old_logs, cleanup_temporary_content

        try:
            db.create_all()

            # Run column migrations for existing databases
            _migrate_animation_settings(app)

            if not Settings.query.filter_by(key='require_auth').first():
                db.session.add(Settings(key='require_auth', value='false'))
            if not Settings.query.filter_by(key='selected_animation').first():
                db.session.add(Settings(key='selected_animation', value='auto'))
            if not User.query.filter_by(email=ADMIN_EMAIL).first():
                db.session.add(User(email=ADMIN_EMAIL, name='Admin', is_admin=True))
            if not AnimationSettings.query.first():
                db.session.add(AnimationSettings(
                    auto_rotate=True,
                    rotation_interval=8,
                    enabled_animations='slide-up,fade-in,slide-left,zoom-in,wave-in',
                    animation_speed=1.0,
                    typewriter_speed=50,
                    auto_cycle=False,
                    display_duration=30,
                    hide_duration=10,
                    cycle_enter_animation='auto',
                    cycle_exit_animation='fade-out-exit',
                    ticker_enabled=True,
                    ticker_duration=6,
                    ticker_delay=4,
                    ticker_enter_animation='fade-in',
                    ticker_exit_animation='fade-out-exit',
                    ticker_end_behavior='loop',
                ))
            db.session.commit()

            cleanup_old_logs()
            cleanup_temporary_content()

            church = Church.query.first()
            if church:
                overlay_state['church'] = {'name': church.name, 'description': church.description}
                overlay_state['colors'] = {
                    'accent':       church.accent_color,
                    'church_label': church.church_label_color,
                    'main_title':   church.main_title_color,
                    'subtitle':     church.subtitle_color,
                    'verse':        church.verse_color
                }

            anim = AnimationSettings.query.first()
            if anim:
                overlay_state['animation_settings'] = _anim_to_dict(anim)

            print("[OK] Database initialised successfully")

        except Exception as e:
            db.session.rollback()
            print(f"[ERROR] Database initialisation error: {e}")

    return app