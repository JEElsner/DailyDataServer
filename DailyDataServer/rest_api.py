from .db import get_user
from flask import (
    Blueprint, g, json, redirect, request, session, url_for, jsonify, Response
)

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import abort

from DailyDataServer.db import get_db

from datetime import datetime

bp = Blueprint('api', __name__, url_prefix='/api')


@bp.errorhandler(400)
def bad_request(err):
    return {'status_code': 400,
            'description': str(err)
            }, 400


@bp.errorhandler(401)
def unauthorized(err):
    return {'status_code': 401,
            'description': str(err)}, 401


@bp.errorhandler(403)
def forbidden(err):
    return {'status_code': 403,
            'description': str(err)
            }, 403


@bp.errorhandler(404)
def not_found(err):
    return {'status_code': 404,
            'description': str(err)
            }, 404


@bp.errorhandler(409)
def conflict(err):
    return {'status_code': 409,
            'description': str(err)
            }, 409


@bp.errorhandler(500)
def internal_service_error(err):
    return {'status_code': 500,
            'description': str(err)}, 500


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
                abort(400, 'Report time is not an integer')
        except KeyError:
            return redirect(url_for('api.add_user'))

        db = get_db()

        if not username:
            abort(400, {'message': 'Username is required.'})
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            abort(409, 'User already exists.')

        if not password:
            abort(400, 'Password is required.')

        if not name:
            abort(400, 'Name is required.')

        if not email:
            abort(400, 'Email is required.')
        elif '@' not in email:
            abort(400, 'Invalid email address')
        # TODO verify email address by sending email to user

        if report_time is None:
            abort(400, 'Report time is required')

        db.execute(
            'INSERT INTO user'
            ' (username, name, email, report_time, password)'
            ' VALUES (?, ?, ?, ?, ?)',
            (username, name, email, report_time,
             generate_password_hash(password))
        )
        db.commit()

        resp = Response(b"")
        resp.status_code = 201
        resp.headers['Location'] = url_for('api.user', username=username)

        return resp
    elif request.method == 'GET':
        return {
            'username': 'string',
            'name': 'string',
            'email': 'string',
            'report_time': 'int',
            'password': 'string',
        }


@bp.route('/user/<username>', methods=('GET',  'PATCH', 'DELETE'))
def user(username):
    db = get_db()

    user = db.execute(
        'SELECT * FROM user WHERE username = ?', (username,)).fetchone()

    if not user:
        abort(404, 'User not found.')

    if request.method == 'GET':
        return {
            'id': user['id'],
            'username': user['username'],
            'name': user['name'],
            'email': user['email'],
            'creation_date': user['creation_date'].isoformat(),
            'report_time': user['report_time']
        }
    elif request.method == 'DELETE':
        fetch = db.execute(
            'DELETE FROM user WHERE username = ?', (username,)).fetchone()
        db.commit()

        return (b"", 204)
    elif request.method == 'PATCH':
        json_data = request.get_json()

        try:
            if json_data['name']:
                db.execute('UPDATE user SET name = ? WHERE username = ?',
                           (json_data['name'], username))
            else:
                abort(400, 'Name must be non-empty.')
        except KeyError:
            pass

        try:
            if json_data['email']:
                db.execute('UPDATE user SET email = ?, email_confirmed = false'
                           ' WHERE username = ?', (json_data['email'], username))
            else:
                abort(400, 'Email must be non-empty.')
        except KeyError:
            pass

        try:
            if json_data['report_time']:
                db.execute('UPDATE user SET report_time = ? WHERE username = ?', (int(
                    json_data['report_time']) % 10080, username))
            else:
                abort(400, 'Report time must be non-empty.')
        except ValueError:
            abort(400, 'Report time must be an integer.')
        except KeyError:
            pass

        try:
            if json_data['new_password']:
                try:
                    password = json_data['password']

                    if check_password_hash(db.execute('SELECT password FROM user WHERE username = ?', (username,)).fetchone()['password'], password):
                        db.execute('UPDATE user SET password = ? WHERE username = ?',
                                   (generate_password_hash(json_data['new_password']), username))
                    else:
                        abort(401, 'Password incorrect.')
                except KeyError:
                    abort(401, 'Must supply current password.')
        except KeyError:
            pass

        try:
            if json_data['username']:
                abort(400, 'Cannot change username.')
        except KeyError:
            pass

        try:
            if json_data['id']:
                abort(400, 'Cannot change user id.')
        except KeyError:
            pass

        db.commit()

        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)).fetchone()

        return {
            'id': user['id'],
            'username': user['username'],
            'name': user['name'],
            'email': user['email'],
            'creation_date': user['creation_date'].isoformat(),
            'report_time': user['report_time']
        }


@bp.route('/user/<username>/activity', methods=('GET', 'POST'))
def activity(username):
    db = get_db()

    user = db.execute(
        'SELECT * FROM user WHERE username = ?', (username,)).fetchone()
    user_id = user['id']

    if not user:
        abort(404, 'User not found.')

    if request.method == 'GET':
        rows = db.execute(
            'SELECT * FROM activity WHERE user_id = ?', (user_id,)).fetchall()

        return jsonify([{
            'id': r['id'],
            'name': r['name'],
            'description': r['description'],
            'parent_activity': r['parent_activity'],
            'is_alias': bool(r['is_alias']),
            'is_placeholder': bool(r['is_placeholder']),
        } for r in rows])
    elif request.method == 'POST':
        json_data = request.get_json()

        name = json_data.get('name', None)
        if not name:
            abort(400, 'Activity name is required')
        elif db.execute('SELECT COUNT(id) FROM activity WHERE'
                        ' user_id = ? AND name = ?', (user_id, name)).fetchone()[0] > 0:
            abort(409, 'Activity already exists.')

        description = json_data.get('description', None)

        parent_activity = None
        try:
            parent_activity = int(json_data.get('parent_activity', None))
        except TypeError:
            pass
        except ValueError:
            abort(400, 'Parent Activity must be an integer.')

        if parent_activity:
            if not db.execute('SELECT id FROM activity WHERE id = ?', (id,)).fetchone():
                abort(400, 'Parent activity does not exist.')

        is_alias = json_data.get('is_alias', False)
        if is_alias and not parent_activity:
            abort(400, 'Alias must have a parent activity.')

        is_placeholder = json_data.get('is_placeholder', False)

        db.execute('INSERT INTO activity'
                   '(name, description, parent_activity, is_alias, is_placeholder, user_id)'
                   'VALUES (?, ?, ?, ?, ?, ?)',
                   (name, description, parent_activity,
                    is_alias, is_placeholder, user_id)
                   )
        db.commit()

        resp = Response(b'')
        resp.status_code = 201
        resp.headers['Location'] = url_for(
            'api.named_activity', username=username, activity_name=name)

        return resp


@bp.route('/user/<username>/activity/<activity_name>', methods=('GET', 'PATCH', 'DELETE'))
def named_activity(username, activity_name):
    db = get_db()

    user = get_user(username)

    if not user:
        abort(404, 'User not found.')

    user_id = user['id']
    activity = db.execute(
        'SELECT * FROM activity where user_id=? AND name=?', (user_id, activity_name)).fetchone()

    if not activity:
        abort(404, 'Activity not found.')

    if request.method == 'GET':
        return {
            'id': activity['id'],
            'name': activity['name'],
            'description': activity['description'],
            'is_alias': bool(activity['is_alias']),
            'is_placeholder': bool(activity['is_placeholder']),
            'parent_activity': activity['parent_activity']
        }
    elif request.method == 'PATCH':
        json_data = request.get_json()

        if json_data.get('id', None):
            abort(400, 'Cannot change activity id.')

        name = json_data.get('name', None)
        if name:
            db.execute('UPDATE activity SET name = ? WHERE name = ?',
                       (name, activity_name))
        else:
            name = activity['name']

        description = json_data.get('description', None)
        if description:
            db.execute('UPDATE activity SET description = ? WHERE name = ?',
                       (description, activity_name))
        else:
            description = activity['description']

        is_placeholder = json_data.get('is_placeholder', None)
        if is_placeholder is not None:
            db.execute('UPDATE activity SET is_placeholder = ? WHERE name = ?',
                       (is_placeholder, activity_name))
        else:
            is_placeholder = activity['is_placeholder']

        parent_activity = json_data.get('parent_activity', None)
        if parent_activity is not None and type(parent_activity) is int and db.execute('SELECT id FROM activity where id=?', (parent_activity,)).fetchone():
            db.execute('UPDATE activity SET parent_activity = ? WHERE name = ?',
                       (parent_activity, activity_name))
        elif parent_activity is not None and type(parent_activity) is int:
            abort(400, 'Parent activity id does not exist.')
        elif parent_activity is not None:
            abort(400, 'Parent activity id must be integer.')
        else:
            parent_activity = activity['parent_activity']

        is_alias = json_data.get('is_alias', None)
        if is_alias is not None and type(is_alias) is bool and parent_activity:
            db.execute('UPDATE activity SET is_alias=? WHERE name=?',
                       (is_alias, activity_name))
        elif is_alias is not None and type(is_alias) is bool:
            abort(400, 'Activity must have parent to be an alias.')
        elif is_alias is not None:
            abort(400, 'is_alias must be a boolean.')
        else:
            is_alias = activity['is_alias']

        db.commit()

        return {
            'name': name,
            'id': activity['id'],
            'is_alias': is_alias,
            'is_placeholder': is_placeholder,
            'parent_activity': parent_activity,
            'description': description
        }

    elif request.method == 'DELETE':
        db.execute('DELETE FROM activity WHERE user_id = ? AND name = ?',
                   (user_id, activity_name))
        db.commit()

        return (b"", 204)


@bp.route('/user/<username>/timelog', methods=('GET', 'POST'))
def timelog(username):
    abort(501)
