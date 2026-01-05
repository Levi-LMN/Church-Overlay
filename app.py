import os
from flask import Flask, render_template, redirect, url_for, request, jsonify, session, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
import time

app = Flask(__name__)
load_dotenv()
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Use absolute path for database and ensure instance folder exists
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')

# Create instance directory if it doesn't exist
os.makedirs(instance_path, exist_ok=True)

# Set proper database URI with absolute path
database_path = os.path.join(instance_path, 'obs_overlay.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'sqlite:///{database_path}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Google OAuth Configuration
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

ADMIN_EMAIL = 'mukuhalevi@gmail.com'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)


def no_cache(view):
    @wraps(view)
    def no_cache_view(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Vary'] = '*'
        return response

    return no_cache_view


# Models
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


class Animation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    css_class = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))


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


# Overlay state
overlay_state = {
    'mode': 'hidden',
    'minister': None,
    'sermon': None,
    'church': None,
    'animation': 'slide-up',
    'timestamp': time.time(),
    'version': 1
}


def update_overlay_timestamp():
    """Helper to update timestamp and version"""
    overlay_state['timestamp'] = time.time()
    overlay_state['version'] = overlay_state.get('version', 0) + 1


def log_activity(action, details=None):
    """Log user activity"""
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


def cleanup_old_logs():
    """Delete logs older than 2 weeks"""
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=14)
        deleted = ActivityLog.query.filter(ActivityLog.timestamp < cutoff_date).delete()
        if deleted > 0:
            db.session.commit()
    except Exception as e:
        db.session.rollback()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def auth_required():
    setting = Settings.query.filter_by(key='require_auth').first()
    return setting and setting.value == 'true'


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin:
            log_activity('UNAUTHORIZED_ACCESS_ATTEMPT', f'Attempted to access admin: {request.path}')
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)

    return decorated_function


def login_optional(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if auth_required() and not current_user.is_authenticated:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# Routes
@app.route('/')
def index():
    if not current_user.is_authenticated:
        if auth_required():
            return redirect(url_for('login'))
        else:
            return redirect(url_for('user_panel'))

    if current_user.is_admin:
        return redirect(url_for('admin'))
    else:
        return redirect(url_for('user_panel'))


@app.route('/login')
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin'))
        return redirect(url_for('user_panel'))

    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    user_info = token.get('userinfo')

    user = User.query.filter_by(email=user_info['email']).first()

    if not user:
        log_activity('LOGIN_DENIED', f"Unauthorized login attempt: {user_info['email']}")
        return render_template('access_denied.html', email=user_info['email'], show_login=False)

    login_user(user)
    log_activity('LOGIN', f"Successful login: {user.email}")

    if user.is_admin:
        return redirect(url_for('admin'))
    return redirect(url_for('user_panel'))


@app.route('/logout')
@login_required
def logout():
    log_activity('LOGOUT', f"User logged out: {current_user.email}")
    logout_user()
    return redirect(url_for('index'))


@app.route('/admin')
@login_required
@admin_required
def admin():
    church = Church.query.first()
    ministers = Minister.query.order_by(Minister.last_used.desc().nullslast()).all()
    sermons = Sermon.query.order_by(Sermon.date.desc()).limit(20).all()
    settings = {s.key: s.value for s in Settings.query.all()}
    animations = Animation.query.all()
    all_users = User.query.order_by(User.created_at.desc()).all()

    cleanup_old_logs()

    return render_template('admin.html',
                           church=church,
                           ministers=ministers,
                           sermons=sermons,
                           settings=settings,
                           animations=animations,
                           all_users=all_users,
                           current_state=overlay_state)


@app.route('/user')
@login_optional
def user_panel():
    church = Church.query.first()
    ministers = Minister.query.order_by(Minister.last_used.desc().nullslast()).all()
    sermons = Sermon.query.order_by(Sermon.date.desc()).all()
    animations = Animation.query.all()
    current_animation = Settings.query.filter_by(key='selected_animation').first()

    return render_template('user.html',
                           church=church,
                           ministers=ministers,
                           sermons=sermons,
                           animations=animations,
                           current_animation=current_animation.value if current_animation else 'auto',
                           current_state=overlay_state,
                           auth_required=auth_required())


@app.route('/display')
@no_cache
def display():
    """Display page with aggressive no-cache headers"""
    response = make_response(render_template('display.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Vary'] = '*'
    return response


# API Routes
@app.route('/api/auth/check')
def check_auth():
    """Check if authentication is required and if user is authenticated"""
    return jsonify({
        'auth_required': auth_required(),
        'authenticated': current_user.is_authenticated
    })


@app.route('/api/overlay/state')
@no_cache
def get_overlay_state():
    """Return overlay state with fresh copy to prevent caching"""
    state_copy = {
        'mode': overlay_state['mode'],
        'minister': overlay_state['minister'].copy() if overlay_state['minister'] else None,
        'sermon': overlay_state['sermon'].copy() if overlay_state['sermon'] else None,
        'church': overlay_state['church'].copy() if overlay_state['church'] else None,
        'animation': overlay_state['animation'],
        'timestamp': overlay_state['timestamp'],  # Use stored timestamp, not new one
        'version': overlay_state.get('version', 1)
    }

    response = make_response(jsonify(state_copy))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/api/overlay/update', methods=['POST'])
@login_optional
def update_overlay():
    data = request.json
    mode = data.get('mode', 'hidden')

    overlay_state['mode'] = mode
    update_overlay_timestamp()

    if 'animation' in data:
        overlay_state['animation'] = data['animation']

    details = f"Mode: {mode}"

    try:
        if mode == 'minister':
            minister_id = data.get('minister_id')
            if minister_id:
                minister = Minister.query.get(minister_id)
                if minister:
                    try:
                        minister.last_used = datetime.utcnow()
                        db.session.commit()
                    except Exception:
                        db.session.rollback()

                    overlay_state['minister'] = {
                        'id': minister.id,
                        'name': minister.name,
                        'title': minister.title
                    }
                    details = f"Displayed minister: {minister.name}"
            else:
                minister_name = data.get('minister_name')
                overlay_state['minister'] = {
                    'name': minister_name,
                    'title': data.get('minister_title')
                }
                details = f"Displayed custom minister: {minister_name}"
            overlay_state['sermon'] = None

        elif mode == 'sermon':
            sermon_id = data.get('sermon_id')
            if sermon_id:
                sermon = Sermon.query.get(sermon_id)
                if sermon:
                    overlay_state['sermon'] = {
                        'id': sermon.id,
                        'minister_name': sermon.minister_name,
                        'title': sermon.title,
                        'bible_verse': sermon.bible_verse
                    }
                    details = f"Displayed sermon: {sermon.title}"
            else:
                sermon_title = data.get('sermon_title')
                overlay_state['sermon'] = {
                    'minister_name': data.get('minister_name'),
                    'title': sermon_title,
                    'bible_verse': data.get('bible_verse')
                }
                details = f"Displayed custom sermon: {sermon_title}"
            overlay_state['minister'] = None

        elif mode == 'hidden':
            overlay_state['minister'] = None
            overlay_state['sermon'] = None
            details = "Overlay hidden"

        church = Church.query.first()
        if church:
            overlay_state['church'] = {
                'name': church.name,
                'description': church.description
            }

        try:
            log_activity('OVERLAY_UPDATE', details)
        except Exception:
            pass

    except Exception:
        pass

    response = make_response(jsonify({'success': True, 'state': overlay_state}))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/api/church', methods=['GET', 'POST'])
@admin_required
def manage_church():
    if request.method == 'POST':
        data = request.json
        church = Church.query.first()
        if not church:
            church = Church()
            db.session.add(church)

        church.name = data.get('name')
        church.description = data.get('description')
        db.session.commit()

        overlay_state['church'] = {
            'name': church.name,
            'description': church.description
        }
        update_overlay_timestamp()

        log_activity('CHURCH_UPDATE', f"Updated church info: {church.name}")
        return jsonify({'success': True})

    church = Church.query.first()
    return jsonify(church.__dict__ if church else {})


@app.route('/api/ministers', methods=['GET', 'POST'])
@admin_required
def manage_ministers():
    if request.method == 'POST':
        data = request.json
        minister = Minister(name=data['name'], title=data.get('title'))
        db.session.add(minister)
        db.session.commit()

        log_activity('MINISTER_ADD', f"Added minister: {minister.name}")
        return jsonify({'success': True, 'id': minister.id})

    ministers = Minister.query.order_by(Minister.last_used.desc().nullslast()).all()
    return jsonify([{'id': m.id, 'name': m.name, 'title': m.title} for m in ministers])


@app.route('/api/ministers/<int:id>', methods=['PUT', 'DELETE'])
@admin_required
def modify_minister(id):
    minister = Minister.query.get_or_404(id)

    if request.method == 'DELETE':
        minister_name = minister.name
        db.session.delete(minister)
        db.session.commit()

        log_activity('MINISTER_DELETE', f"Deleted minister: {minister_name}")
        return jsonify({'success': True})

    if request.method == 'PUT':
        data = request.json
        old_name = minister.name
        minister.name = data.get('name', minister.name)
        minister.title = data.get('title', minister.title)
        db.session.commit()

        log_activity('MINISTER_UPDATE', f"Updated minister: {old_name} -> {minister.name}")
        return jsonify({'success': True})


@app.route('/api/sermons', methods=['GET', 'POST'])
@admin_required
def manage_sermons():
    if request.method == 'POST':
        data = request.json
        sermon = Sermon(
            title=data['title'],
            minister_name=data.get('minister_name'),
            bible_verse=data.get('bible_verse')
        )
        db.session.add(sermon)
        db.session.commit()

        log_activity('SERMON_ADD', f"Added sermon: {sermon.title}")
        return jsonify({'success': True, 'id': sermon.id})

    sermons = Sermon.query.order_by(Sermon.date.desc()).all()
    return jsonify([{
        'id': s.id,
        'title': s.title,
        'minister_name': s.minister_name,
        'bible_verse': s.bible_verse,
        'date': s.date.isoformat()
    } for s in sermons])


@app.route('/api/sermons/<int:id>', methods=['PUT', 'DELETE'])
@admin_required
def modify_sermon(id):
    sermon = Sermon.query.get_or_404(id)

    if request.method == 'DELETE':
        sermon_title = sermon.title
        db.session.delete(sermon)
        db.session.commit()

        log_activity('SERMON_DELETE', f"Deleted sermon: {sermon_title}")
        return jsonify({'success': True})

    if request.method == 'PUT':
        data = request.json
        old_title = sermon.title
        sermon.title = data.get('title', sermon.title)
        sermon.minister_name = data.get('minister_name', sermon.minister_name)
        sermon.bible_verse = data.get('bible_verse', sermon.bible_verse)
        db.session.commit()

        log_activity('SERMON_UPDATE', f"Updated sermon: {old_title} -> {sermon.title}")
        return jsonify({'success': True})


@app.route('/api/animations', methods=['GET', 'POST'])
@admin_required
def manage_animations():
    if request.method == 'POST':
        data = request.json
        animation = Animation(
            name=data['name'],
            css_class=data['css_class'],
            description=data.get('description')
        )
        db.session.add(animation)
        db.session.commit()

        log_activity('ANIMATION_ADD', f"Added animation: {animation.name}")
        return jsonify({'success': True, 'id': animation.id})

    animations = Animation.query.all()
    return jsonify([{
        'id': a.id,
        'name': a.name,
        'css_class': a.css_class,
        'description': a.description
    } for a in animations])


@app.route('/api/animations/<int:id>', methods=['DELETE'])
@admin_required
def delete_animation(id):
    animation = Animation.query.get_or_404(id)
    animation_name = animation.name
    db.session.delete(animation)
    db.session.commit()

    log_activity('ANIMATION_DELETE', f"Deleted animation: {animation_name}")
    return jsonify({'success': True})


@app.route('/api/animation/select', methods=['POST'])
@login_optional
def select_animation():
    data = request.json
    animation = data.get('animation', 'auto')

    setting = Settings.query.filter_by(key='selected_animation').first()
    if not setting:
        setting = Settings(key='selected_animation')
        db.session.add(setting)

    setting.value = animation
    db.session.commit()

    if animation != 'auto':
        overlay_state['animation'] = animation

    update_overlay_timestamp()

    log_activity('ANIMATION_SELECT', f"Selected animation: {animation}")
    return jsonify({'success': True})


@app.route('/api/users', methods=['POST'])
@admin_required
def add_user():
    data = request.json
    email = data.get('email')
    is_admin = data.get('is_admin', False)

    if not email:
        return jsonify({'error': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'error': 'User already exists'}), 400

    user = User(email=email, name=data.get('name', email), is_admin=is_admin)
    db.session.add(user)
    db.session.commit()

    log_activity('USER_ADD', f"Added user: {user.email} (Admin: {is_admin})")
    return jsonify({'success': True, 'id': user.id})


@app.route('/api/users/<int:id>', methods=['PUT', 'DELETE'])
@admin_required
def modify_user(id):
    user = User.query.get_or_404(id)

    if request.method == 'DELETE':
        if user.email == ADMIN_EMAIL:
            return jsonify({'error': 'Cannot delete primary admin'}), 400

        user_email = user.email
        db.session.delete(user)
        db.session.commit()

        log_activity('USER_DELETE', f"Deleted user: {user_email}")
        return jsonify({'success': True})

    if request.method == 'PUT':
        data = request.json

        if user.email == ADMIN_EMAIL and not data.get('is_admin', True):
            return jsonify({'error': 'Cannot remove admin privileges from primary admin'}), 400

        old_admin = user.is_admin
        user.name = data.get('name', user.name)
        user.is_admin = data.get('is_admin', user.is_admin)
        db.session.commit()

        if old_admin != user.is_admin:
            role = 'Admin' if user.is_admin else 'User'
            log_activity('USER_ROLE_CHANGE', f"Changed {user.email} role to: {role}")

        return jsonify({'success': True})


@app.route('/api/settings', methods=['POST'])
@admin_required
def update_settings():
    data = request.json
    changes = []

    for key, value in data.items():
        setting = Settings.query.filter_by(key=key).first()
        if not setting:
            setting = Settings(key=key)
            db.session.add(setting)
        setting.value = value
        changes.append(f"{key}={value}")

    db.session.commit()

    log_activity('SETTINGS_UPDATE', f"Updated settings: {', '.join(changes)}")
    return jsonify({'success': True})


@app.route('/api/activity-logs', methods=['GET'])
@admin_required
def get_activity_logs():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    action_filter = request.args.get('action', None)

    query = ActivityLog.query

    if action_filter:
        query = query.filter(ActivityLog.action == action_filter)

    logs = query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'logs': [log.to_dict() for log in logs.items],
        'total': logs.total,
        'pages': logs.pages,
        'current_page': logs.page
    })


@app.route('/api/activity-logs/<int:id>', methods=['DELETE'])
@admin_required
def delete_activity_log(id):
    log = ActivityLog.query.get_or_404(id)
    db.session.delete(log)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/activity-logs/clear', methods=['POST'])
@admin_required
def clear_activity_logs():
    data = request.json
    days = data.get('days', 30)

    cutoff_date = datetime.utcnow() - timedelta(days=days)
    deleted = ActivityLog.query.filter(ActivityLog.timestamp < cutoff_date).delete()
    db.session.commit()

    log_activity('LOGS_CLEARED', f"Cleared {deleted} logs older than {days} days")
    return jsonify({'success': True, 'deleted': deleted})


@app.route('/api/activity-logs/mass-delete', methods=['POST'])
@admin_required
def mass_delete_logs():
    data = request.json
    log_ids = data.get('ids', [])

    if not log_ids:
        return jsonify({'error': 'No log IDs provided'}), 400

    deleted_count = ActivityLog.query.filter(ActivityLog.id.in_(log_ids)).delete(synchronize_session=False)
    db.session.commit()

    log_activity('LOGS_MASS_DELETE',
                 f"Mass deleted {deleted_count} activity logs (IDs: {log_ids[:10]}{'...' if len(log_ids) > 10 else ''})")
    return jsonify({'success': True, 'deleted': deleted_count})


# Initialize database
with app.app_context():
    try:
        db.create_all()

        # Create default settings
        if not Settings.query.filter_by(key='require_auth').first():
            db.session.add(Settings(key='require_auth', value='false'))

        if not Settings.query.filter_by(key='selected_animation').first():
            db.session.add(Settings(key='selected_animation', value='auto'))

        # Seed admin user if doesn't exist
        admin_user = User.query.filter_by(email=ADMIN_EMAIL).first()
        if not admin_user:
            admin_user = User(
                email=ADMIN_EMAIL,
                name='Admin',
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()

        # Clear old animations
        Animation.query.delete()
        db.session.commit()

        cleanup_old_logs()

        # Load church info into overlay state
        church = Church.query.first()
        if church:
            overlay_state['church'] = {
                'name': church.name,
                'description': church.description
            }

    except Exception as e:
        db.session.rollback()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)