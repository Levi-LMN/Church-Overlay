from flask import Blueprint, render_template, request
from flask_login import login_required

from extensions import overlay_state, ADMIN_EMAIL, state_update_queues
from utils.helpers import admin_required, cleanup_old_logs

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/')
@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    from models import Church, Settings, AnimationSettings, Minister, Sermon, User, ActivityLog

    church = Church.query.first()
    settings = {s.key: s.value for s in Settings.query.all()}
    animation_settings = AnimationSettings.query.first()
    cleanup_old_logs()

    recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(8).all()

    return render_template('admin/dashboard.html',
                           church=church,
                           settings=settings,
                           animation_settings=animation_settings,
                           current_state=overlay_state,
                           ministers_count=Minister.query.count(),
                           sermons_count=Sermon.query.count(),
                           users_count=User.query.count(),
                           sse_clients=len(state_update_queues),
                           recent_logs=recent_logs)


@admin_bp.route('/content')
@login_required
@admin_required
def content():
    from models import Minister, Sermon

    ministers = Minister.query.order_by(Minister.last_used.desc().nullslast()).all()
    sermons   = Sermon.query.order_by(Sermon.date.desc()).limit(50).all()

    return render_template('admin/content.html',
                           ministers=ministers,
                           sermons=sermons)


@admin_bp.route('/users')
@login_required
@admin_required
def users():
    from models import User

    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html',
                           users=all_users,
                           admin_email=ADMIN_EMAIL)


@admin_bp.route('/settings')
@login_required
@admin_required
def settings():
    from models import Church, Settings, AnimationSettings

    church = Church.query.first()
    app_settings = {s.key: s.value for s in Settings.query.all()}
    animation_settings = AnimationSettings.query.first()

    return render_template('admin/settings.html',
                           church=church,
                           settings=app_settings,
                           animation_settings=animation_settings)


@admin_bp.route('/logs')
@login_required
@admin_required
def logs():
    from models import ActivityLog

    page     = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    logs_paginated = (ActivityLog.query
                      .order_by(ActivityLog.timestamp.desc())
                      .paginate(page=page, per_page=per_page, error_out=False))

    return render_template('admin/logs.html',
                           logs=logs_paginated.items,
                           pagination=logs_paginated)