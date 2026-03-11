from flask import Blueprint, redirect, render_template, url_for
from flask_login import current_user, login_user, logout_user, login_required

from extensions import oauth          # <- from extensions, NOT from app
from utils.helpers import log_activity

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login')
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('user.panel'))

    from models import Church
    church = Church.query.first()
    return render_template('login.html', church=church)


@auth_bp.route('/login/google')
def login_google():
    """Initiate the Google OAuth flow."""
    redirect_uri = url_for('auth.authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@auth_bp.route('/authorize')
def authorize():
    from models import User

    token = oauth.google.authorize_access_token()
    user_info = token.get('userinfo')

    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        log_activity('LOGIN_DENIED',
                     f"Unauthorised login attempt: {user_info['email']}")
        return render_template('access_denied.html',
                               email=user_info['email'], show_login=False)

    login_user(user)
    log_activity('LOGIN', f"Successful login: {user.email}")

    if user.is_admin:
        return redirect(url_for('admin.dashboard'))
    return redirect(url_for('user.panel'))


@auth_bp.route('/logout')
@login_required
def logout():
    log_activity('LOGOUT', f"User logged out: {current_user.email}")
    logout_user()
    return redirect(url_for('auth.login'))