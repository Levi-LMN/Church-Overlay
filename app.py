import os

from dotenv import load_dotenv
from flask import Flask, redirect, url_for
from flask_login import current_user

from extensions import db, login_manager, oauth, csrf, overlay_state, ADMIN_EMAIL


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

    # WTF CSRF -- exempt the SSE stream and JSON API routes
    app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # manual exemptions below

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

    # Exempt the entire API blueprint from CSRF (JSON API with no forms)
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

            if not Settings.query.filter_by(key='require_auth').first():
                db.session.add(Settings(key='require_auth', value='false'))
            if not Settings.query.filter_by(key='selected_animation').first():
                db.session.add(Settings(key='selected_animation', value='auto'))
            if not User.query.filter_by(email=ADMIN_EMAIL).first():
                db.session.add(User(email=ADMIN_EMAIL, name='Admin', is_admin=True))
            if not AnimationSettings.query.first():
                db.session.add(AnimationSettings(
                    auto_rotate=True,
                    rotation_interval=5,
                    enabled_animations='slide-up,fade-in,slide-left,zoom-in,wave-in'
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
                overlay_state['animation_settings'] = {
                    'auto_rotate':        anim.auto_rotate,
                    'rotation_interval':  anim.rotation_interval,
                    'enabled_animations': anim.enabled_animations.split(',')
                }

            print("[OK] Database initialised successfully")

        except Exception as e:
            db.session.rollback()
            print(f"[ERROR] Database initialisation error: {e}")

    return app