from flask import (
    Blueprint, g, redirect, request, session, url_for
)

from werkzeug.security import generate_password_hash
from werkzeug.exceptions import abort

from DailyDataServer.db import get_db

from datetime import datetime

bp = Blueprint('api', __name__, url_prefix='/api')


@bp.route('/', methods=('GET',))
def api():
    return {
        'message': 'This is the REST api for the timelog.',
        'user_url': url_for('api.user'),
        'activity_url': url_for('api.activity'),
        'timelog_url': url_for('api.timelog')
    }


@bp.route('/user', methods=('GET', 'POST'))
def add_user():
    if request.method == 'POST':
        json_data = request.get_json()

        if not json_data:
            abort(400, {'message': 'Must supply JSON data.'})

        try:
            username = json_data['username']
            name = json_data['name']
            email = json_data['email']
            password = json_data['password']

            report_time = None
            try:
                report_time = int(json_data['report_time']) % 10080
            except ValueError:
                abort(400, {'message': 'Report time is not an integer'})
        except KeyError:
            return redirect(url_for('api.add_user'))

        db = get_db()

        if not username:
            abort(400, {'message': 'Username is required.'})
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            abort(400, {'message': 'User already exists.'})

        if not password:
            abort(400, {'message': 'Password is required.'})

        if not name:
            abort(400, {'message': 'Name is required.'})

        if not email:
            abort(400, {'message': 'Email is required.'})
        elif '@' not in email:
            abort(400, {'message': 'Invalid email address'})
        # TODO verify email address by sending email to user

        if report_time is None:
            abort(400, {'message': 'Report time is required'})

        db.execute(
            'INSERT INTO user'
            ' (username, name, email, report_time, password, creation_date)'
            ' VALUES (?, ?, ?, ?, ?, ?)',
            (username, name, email, report_time,
             generate_password_hash(password), datetime.utcnow())
        )
        db.commit()

        return redirect(url_for('api.user', username=username))
    elif request.method == 'GET':
        return {
            'username': 'string',
            'name': 'string',
            'email': 'string',
            'report_time': 'int',
            'password': 'string',
        }


@bp.route('/user/<username>', methods=('GET',  'POST', 'DELETE'))
def user(username):
    abort(501)


@bp.route('/user/<username>/activity', methods=('GET', 'POST'))
def activity(username):
    abort(501)


@bp.route('/user/<username>/timelog', methods=('GET', 'POST'))
def timelog(username):
    abort(501)
