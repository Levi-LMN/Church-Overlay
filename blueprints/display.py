from flask import Blueprint, make_response, render_template

from utils.helpers import no_cache

display_bp = Blueprint('display', __name__)


@display_bp.route('/')
@no_cache
def show():
    """Display page with aggressive no-cache headers -- DO NOT MODIFY."""
    response = make_response(render_template('display.html'))
    response.headers['Cache-Control'] = (
        'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    )
    response.headers['Pragma']  = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Vary']    = '*'
    return response