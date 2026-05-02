import json
import time
from datetime import datetime, timedelta

from flask import Blueprint, Response, jsonify, make_response, request
from flask_login import current_user

from extensions import (ADMIN_EMAIL, db, overlay_state, state_lock)
from utils.helpers import (admin_required, auth_required as check_auth_required,
                           log_activity, login_optional, no_cache,
                           notify_state_change)

api_bp = Blueprint('api', __name__)


def _anim_to_dict(anim):
    """Serialize AnimationSettings to the overlay_state dict format."""
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
    }


# ============================================================================
# AUTHENTICATION & GENERAL
# ============================================================================

@api_bp.route('/auth/check')
def check_auth():
    return jsonify({
        'auth_required': check_auth_required(),
        'authenticated': current_user.is_authenticated
    })


# ============================================================================
# OVERLAY STATE & STREAMING
# ============================================================================

@api_bp.route('/overlay/state')
@no_cache
def get_overlay_state():
    with state_lock:
        state = overlay_state.copy()
    response = make_response(jsonify(state))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@api_bp.route('/overlay/update', methods=['POST'])
@login_optional
def update_overlay():
    from models import AnimationSettings, Church, Minister, Sermon, TemporaryContent

    data = request.json
    mode = data.get('mode', 'hidden')

    with state_lock:
        overlay_state['mode'] = mode
        if 'animation' in data:
            overlay_state['animation'] = data['animation']
        details = f"Mode: {mode}"

        try:
            if mode == 'minister':
                minister_id = data.get('minister_id')
                temp_id = data.get('temp_minister_id')

                if minister_id:
                    minister = db.session.get(Minister, minister_id)
                    if minister:
                        minister.last_used = datetime.utcnow()
                        db.session.commit()
                        overlay_state['minister'] = {
                            'id': minister.id, 'name': minister.name, 'title': minister.title
                        }
                        details = f"Displayed minister: {minister.name}"
                elif temp_id:
                    temp = db.session.get(TemporaryContent, temp_id)
                    if temp:
                        temp.last_used = datetime.utcnow()
                        db.session.commit()
                        overlay_state['minister'] = {
                            'temp_id': temp.id, 'name': temp.name, 'title': temp.title
                        }
                        details = f"Displayed temp minister: {temp.name}"
                else:
                    minister_name  = data.get('minister_name')
                    minister_title = data.get('minister_title')
                    if current_user.is_authenticated and minister_name:
                        temp = (TemporaryContent.query
                                .filter_by(content_type='minister',
                                           name=minister_name,
                                           title=minister_title or '')
                                .first())
                        if temp:
                            temp.last_used = datetime.utcnow()
                        else:
                            temp = TemporaryContent(
                                content_type='minister', name=minister_name,
                                title=minister_title, created_by=current_user.id,
                                last_used=datetime.utcnow()
                            )
                            db.session.add(temp)
                        db.session.commit()
                    overlay_state['minister'] = {'name': minister_name, 'title': minister_title}
                    details = f"Displayed custom minister: {minister_name}"
                overlay_state['sermon'] = None

            elif mode == 'sermon':
                sermon_id = data.get('sermon_id')
                temp_id   = data.get('temp_sermon_id')

                if sermon_id:
                    sermon = db.session.get(Sermon, sermon_id)
                    if sermon:
                        overlay_state['sermon'] = {
                            'id': sermon.id, 'minister_name': sermon.minister_name,
                            'title': sermon.title, 'bible_verse': sermon.bible_verse
                        }
                        details = f"Displayed sermon: {sermon.title}"
                elif temp_id:
                    temp = db.session.get(TemporaryContent, temp_id)
                    if temp:
                        temp.last_used = datetime.utcnow()
                        db.session.commit()
                        overlay_state['sermon'] = {
                            'temp_id': temp.id, 'minister_name': temp.minister_name,
                            'title': temp.title, 'bible_verse': temp.bible_verse
                        }
                        details = f"Displayed temp sermon: {temp.title}"
                else:
                    sermon_title   = data.get('sermon_title')
                    minister_name  = data.get('minister_name')
                    bible_verse    = data.get('bible_verse')
                    if current_user.is_authenticated and sermon_title:
                        temp = (TemporaryContent.query
                                .filter_by(content_type='sermon',
                                           title=sermon_title,
                                           minister_name=minister_name or '',
                                           bible_verse=bible_verse or '')
                                .first())
                        if temp:
                            temp.last_used = datetime.utcnow()
                        else:
                            temp = TemporaryContent(
                                content_type='sermon', title=sermon_title,
                                minister_name=minister_name, bible_verse=bible_verse,
                                created_by=current_user.id, last_used=datetime.utcnow()
                            )
                            db.session.add(temp)
                        db.session.commit()
                    overlay_state['sermon'] = {
                        'minister_name': minister_name,
                        'title': sermon_title,
                        'bible_verse': bible_verse
                    }
                    details = f"Displayed custom sermon: {sermon_title}"
                overlay_state['minister'] = None

            elif mode == 'hidden':
                overlay_state['minister'] = None
                overlay_state['sermon']   = None
                details = "Overlay hidden"

            church = Church.query.first()
            if church:
                overlay_state['church'] = {'name': church.name, 'description': church.description}
                overlay_state['colors'] = {
                    'accent': church.accent_color, 'church_label': church.church_label_color,
                    'main_title': church.main_title_color, 'subtitle': church.subtitle_color,
                    'verse': church.verse_color
                }

            anim = AnimationSettings.query.first()
            if anim:
                overlay_state['animation_settings'] = _anim_to_dict(anim)

            log_activity('OVERLAY_UPDATE', details)

        except Exception as e:
            print(f"Error updating overlay: {e}")

    notify_state_change()

    response = make_response(jsonify({'success': True, 'state': overlay_state.copy()}))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


# ============================================================================
# CHURCH MANAGEMENT
# ============================================================================

@api_bp.route('/church', methods=['GET', 'POST'])
@admin_required
def manage_church():
    from models import Church

    if request.method == 'POST':
        data = request.json
        church = Church.query.first()
        if not church:
            church = Church()
            db.session.add(church)

        church.name               = data.get('name')
        church.description        = data.get('description')
        church.accent_color       = data.get('accent_color', '#10b981')
        church.church_label_color = data.get('church_label_color', '#10b981')
        church.main_title_color   = data.get('main_title_color', '#ffffff')
        church.subtitle_color     = data.get('subtitle_color', 'rgba(255, 255, 255, 0.85)')
        church.verse_color        = data.get('verse_color', '#10b981')
        db.session.commit()

        with state_lock:
            overlay_state['church'] = {'name': church.name, 'description': church.description}
            overlay_state['colors'] = {
                'accent': church.accent_color, 'church_label': church.church_label_color,
                'main_title': church.main_title_color, 'subtitle': church.subtitle_color,
                'verse': church.verse_color
            }

        notify_state_change()
        log_activity('CHURCH_UPDATE', f"Updated church info: {church.name}")
        return jsonify({'success': True})

    church = Church.query.first()
    return jsonify(church.__dict__ if church else {})


# ============================================================================
# MINISTER MANAGEMENT
# ============================================================================

@api_bp.route('/ministers', methods=['GET'])
@login_optional
def list_ministers():
    from models import Minister
    ministers = Minister.query.order_by(Minister.last_used.desc().nulls_last()).all()
    return jsonify([{'id': m.id, 'name': m.name, 'title': m.title} for m in ministers])


@api_bp.route('/ministers', methods=['POST'])
@admin_required
def create_minister():
    from models import Minister
    data = request.json
    minister = Minister(name=data['name'], title=data.get('title'))
    db.session.add(minister)
    db.session.commit()
    log_activity('MINISTER_ADD', f"Added minister: {minister.name}")
    return jsonify({'success': True, 'id': minister.id})


@api_bp.route('/ministers/<int:id>', methods=['PUT', 'DELETE'])
@admin_required
def modify_minister(id):
    from models import Minister

    minister = Minister.query.get_or_404(id)

    if request.method == 'DELETE':
        name = minister.name
        db.session.delete(minister)
        db.session.commit()
        log_activity('MINISTER_DELETE', f"Deleted minister: {name}")
        return jsonify({'success': True})

    data = request.json
    old_name = minister.name
    minister.name  = data.get('name', minister.name)
    minister.title = data.get('title', minister.title)
    db.session.commit()
    log_activity('MINISTER_UPDATE', f"Updated minister: {old_name} -> {minister.name}")
    return jsonify({'success': True})


# ============================================================================
# SERMON MANAGEMENT
# ============================================================================

@api_bp.route('/sermons', methods=['GET'])
@login_optional
def list_sermons():
    from models import Sermon
    sermons = Sermon.query.order_by(Sermon.date.desc()).all()
    return jsonify([{
        'id': s.id, 'title': s.title, 'minister_name': s.minister_name,
        'bible_verse': s.bible_verse, 'date': s.date.isoformat()
    } for s in sermons])


@api_bp.route('/sermons', methods=['POST'])
@admin_required
def create_sermon():
    from models import Sermon
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


@api_bp.route('/sermons/<int:id>', methods=['PUT', 'DELETE'])
@admin_required
def modify_sermon(id):
    from models import Sermon

    sermon = Sermon.query.get_or_404(id)

    if request.method == 'DELETE':
        title = sermon.title
        db.session.delete(sermon)
        db.session.commit()
        log_activity('SERMON_DELETE', f"Deleted sermon: {title}")
        return jsonify({'success': True})

    data = request.json
    old_title = sermon.title
    sermon.title         = data.get('title', sermon.title)
    sermon.minister_name = data.get('minister_name', sermon.minister_name)
    sermon.bible_verse   = data.get('bible_verse', sermon.bible_verse)
    db.session.commit()
    log_activity('SERMON_UPDATE', f"Updated sermon: {old_title} -> {sermon.title}")
    return jsonify({'success': True})


# ============================================================================
# TEMPORARY CONTENT MANAGEMENT
# ============================================================================

@api_bp.route('/temporary-content', methods=['GET'])
def get_temporary_content():
    from models import TemporaryContent

    temp_ministers = (TemporaryContent.query
                      .filter_by(content_type='minister')
                      .order_by(TemporaryContent.last_used.desc().nulls_last())
                      .limit(10).all())

    temp_sermons = (TemporaryContent.query
                    .filter_by(content_type='sermon')
                    .order_by(TemporaryContent.last_used.desc().nulls_last())
                    .limit(10).all())

    return jsonify({
        'ministers': [{'id': t.id, 'name': t.name, 'title': t.title,
                       'content_type': 'minister'} for t in temp_ministers],
        'sermons':   [{'id': t.id, 'title': t.title, 'minister_name': t.minister_name,
                       'bible_verse': t.bible_verse, 'content_type': 'sermon'}
                      for t in temp_sermons]
    })


@api_bp.route('/temporary-content/<int:id>', methods=['DELETE'])
def delete_temporary_content(id):
    from models import TemporaryContent

    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401

    temp = TemporaryContent.query.get_or_404(id)
    if temp.created_by != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    name = temp.name or temp.title
    content_type = temp.content_type
    db.session.delete(temp)
    db.session.commit()
    log_activity('TEMP_CONTENT_DELETE', f"Deleted temporary {content_type}: {name}")
    return jsonify({'success': True})


# ============================================================================
# SHARED CUSTOM CONTENT
# ============================================================================

CUSTOM_KEYS = [
    'custom_minister_name',
    'custom_minister_title',
    'custom_sermon_title',
    'custom_sermon_minister',
    'custom_sermon_verse',
]


@api_bp.route('/custom-content', methods=['GET'])
def get_custom_content():
    from models import Settings
    result = {}
    for key in CUSTOM_KEYS:
        setting = Settings.query.filter_by(key=key).first()
        result[key] = setting.value if setting else ''
    return jsonify(result)


@api_bp.route('/custom-content', methods=['POST'])
@login_optional
def save_custom_content():
    from models import Settings, TemporaryContent
    data = request.json or {}
    saved = []

    for key in CUSTOM_KEYS:
        if key in data:
            setting = Settings.query.filter_by(key=key).first()
            if not setting:
                setting = Settings(key=key)
                db.session.add(setting)
            setting.value = data[key]
            saved.append(key)

    if data.get('custom_minister_name'):
        name  = data['custom_minister_name']
        title = data.get('custom_minister_title', '')
        temp  = (TemporaryContent.query
                 .filter_by(content_type='minister', name=name, title=title)
                 .first())
        if temp:
            temp.last_used = datetime.utcnow()
        else:
            temp = TemporaryContent(
                content_type='minister', name=name, title=title,
                created_by=current_user.id if current_user.is_authenticated else None,
                last_used=datetime.utcnow()
            )
            db.session.add(temp)

    if data.get('custom_sermon_title'):
        title   = data['custom_sermon_title']
        mname   = data.get('custom_sermon_minister', '')
        verse   = data.get('custom_sermon_verse', '')
        temp    = (TemporaryContent.query
                   .filter_by(content_type='sermon', title=title,
                               minister_name=mname, bible_verse=verse)
                   .first())
        if temp:
            temp.last_used = datetime.utcnow()
        else:
            temp = TemporaryContent(
                content_type='sermon', title=title,
                minister_name=mname, bible_verse=verse,
                created_by=current_user.id if current_user.is_authenticated else None,
                last_used=datetime.utcnow()
            )
            db.session.add(temp)

    db.session.commit()
    log_activity('CUSTOM_CONTENT_SAVE', f"Saved: {', '.join(saved)}")
    return jsonify({'success': True})


# ============================================================================
# ANIMATION SETTINGS
# ============================================================================

@api_bp.route('/animation-settings', methods=['GET', 'POST'])
@admin_required
def manage_animation_settings():
    from models import AnimationSettings

    if request.method == 'POST':
        data = request.json
        settings = AnimationSettings.query.first()
        if not settings:
            settings = AnimationSettings()
            db.session.add(settings)

        settings.auto_rotate            = data.get('auto_rotate', True)
        settings.rotation_interval      = int(data.get('rotation_interval', 8))
        settings.enabled_animations     = data.get('enabled_animations',
                                                    'slide-up,fade-in,slide-left,zoom-in,wave-in')
        settings.animation_speed        = float(data.get('animation_speed', 1.0))
        settings.typewriter_speed       = int(data.get('typewriter_speed', 50))
        settings.auto_cycle             = data.get('auto_cycle', False)
        settings.display_duration       = int(data.get('display_duration', 30))
        settings.hide_duration          = int(data.get('hide_duration', 10))
        settings.cycle_enter_animation  = data.get('cycle_enter_animation', 'auto')
        settings.cycle_exit_animation   = data.get('cycle_exit_animation', 'fade-out-exit')
        db.session.commit()

        with state_lock:
            overlay_state['animation_settings'] = _anim_to_dict(settings)

        notify_state_change()
        log_activity('ANIMATION_SETTINGS_UPDATE', "Updated animation settings")
        return jsonify({'success': True})

    settings = AnimationSettings.query.first()
    if settings:
        return jsonify(_anim_to_dict(settings))
    return jsonify({
        'auto_rotate': True, 'rotation_interval': 8,
        'enabled_animations': 'slide-up,fade-in,slide-left,zoom-in,wave-in',
        'animation_speed': 1.0, 'typewriter_speed': 50,
        'auto_cycle': False, 'display_duration': 30, 'hide_duration': 10,
        'cycle_enter_animation': 'auto', 'cycle_exit_animation': 'fade-out-exit',
    })


# ============================================================================
# USER MANAGEMENT
# ============================================================================

@api_bp.route('/users', methods=['POST'])
@admin_required
def add_user():
    from models import User

    data  = request.json
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'User already exists'}), 400

    user = User(email=email, name=data.get('name', email),
                is_admin=data.get('is_admin', False))
    db.session.add(user)
    db.session.commit()
    log_activity('USER_ADD', f"Added user: {user.email} (Admin: {user.is_admin})")
    return jsonify({'success': True, 'id': user.id})


@api_bp.route('/users/<int:id>', methods=['PUT', 'DELETE'])
@admin_required
def modify_user(id):
    from models import User

    user = User.query.get_or_404(id)

    if request.method == 'DELETE':
        if user.email == ADMIN_EMAIL:
            return jsonify({'error': 'Cannot delete primary admin'}), 400
        email = user.email
        db.session.delete(user)
        db.session.commit()
        log_activity('USER_DELETE', f"Deleted user: {email}")
        return jsonify({'success': True})

    data = request.json
    if user.email == ADMIN_EMAIL and not data.get('is_admin', True):
        return jsonify({'error': 'Cannot remove admin privileges from primary admin'}), 400

    old_admin   = user.is_admin
    user.name   = data.get('name', user.name)
    user.is_admin = data.get('is_admin', user.is_admin)
    db.session.commit()

    if old_admin != user.is_admin:
        role = 'Admin' if user.is_admin else 'User'
        log_activity('USER_ROLE_CHANGE', f"Changed {user.email} role to: {role}")

    return jsonify({'success': True})


# ============================================================================
# SETTINGS MANAGEMENT
# ============================================================================

@api_bp.route('/settings', methods=['POST'])
@admin_required
def update_settings():
    from models import Settings

    data    = request.json
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


# ============================================================================
# ACTIVITY LOGS
# ============================================================================

@api_bp.route('/activity-logs', methods=['GET'])
@admin_required
def get_activity_logs():
    from models import ActivityLog

    page          = request.args.get('page', 1, type=int)
    per_page      = request.args.get('per_page', 50, type=int)
    action_filter = request.args.get('action')

    query = ActivityLog.query
    if action_filter:
        query = query.filter(ActivityLog.action == action_filter)

    logs = query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify({
        'logs':         [l.to_dict() for l in logs.items],
        'total':        logs.total,
        'pages':        logs.pages,
        'current_page': logs.page
    })


@api_bp.route('/activity-logs/<int:id>', methods=['DELETE'])
@admin_required
def delete_activity_log(id):
    from models import ActivityLog

    log = ActivityLog.query.get_or_404(id)
    db.session.delete(log)
    db.session.commit()
    return jsonify({'success': True})


@api_bp.route('/activity-logs/clear', methods=['POST'])
@admin_required
def clear_activity_logs():
    from models import ActivityLog

    days    = request.json.get('days', 30)
    cutoff  = datetime.utcnow() - timedelta(days=days)
    deleted = ActivityLog.query.filter(ActivityLog.timestamp < cutoff).delete()
    db.session.commit()
    log_activity('LOGS_CLEARED', f"Cleared {deleted} logs older than {days} days")
    return jsonify({'success': True, 'deleted': deleted})


@api_bp.route('/activity-logs/mass-delete', methods=['POST'])
@admin_required
def mass_delete_logs():
    from models import ActivityLog

    log_ids = request.json.get('ids', [])
    if not log_ids:
        return jsonify({'error': 'No log IDs provided'}), 400

    deleted = ActivityLog.query.filter(ActivityLog.id.in_(log_ids)).delete(
        synchronize_session=False
    )
    db.session.commit()
    log_activity('LOGS_MASS_DELETE', f"Mass deleted {deleted} activity logs")
    return jsonify({'success': True, 'deleted': deleted})