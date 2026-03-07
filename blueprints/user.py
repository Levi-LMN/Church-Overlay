from flask import Blueprint, render_template
from flask_login import current_user

from extensions import overlay_state                           # <- extensions
from utils.helpers import login_optional, auth_required as check_auth_required

user_bp = Blueprint('user', __name__)


@user_bp.route('/')
@user_bp.route('/panel')
@login_optional
def panel():
    from models import Church, Minister, Sermon, TemporaryContent, AnimationSettings

    church    = Church.query.first()
    ministers = Minister.query.order_by(Minister.last_used.desc().nulls_last()).all()
    sermons   = Sermon.query.order_by(Sermon.date.desc()).all()

    # Shared across all users -- most recently used first
    temp_ministers = (TemporaryContent.query
                      .filter_by(content_type='minister')
                      .order_by(TemporaryContent.last_used.desc().nulls_last())
                      .limit(10).all())
    temp_sermons   = (TemporaryContent.query
                      .filter_by(content_type='sermon')
                      .order_by(TemporaryContent.last_used.desc().nulls_last())
                      .limit(10).all())

    animation_settings = AnimationSettings.query.first()

    return render_template('user.html',
                           church=church,
                           ministers=ministers,
                           sermons=sermons,
                           temp_ministers=temp_ministers,
                           temp_sermons=temp_sermons,
                           animation_settings=animation_settings,
                           current_state=overlay_state,
                           auth_required=check_auth_required())