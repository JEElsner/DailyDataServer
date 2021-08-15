from typing import Union
from flask.app import Flask
import pytest

from DailyDataServer.db import get_db

import base64
import flask
from flask import (
    url_for
)
from flask.testing import FlaskClient
import werkzeug
from werkzeug.security import check_password_hash

BASIC_CREDENTIAL = base64.b64encode(b'test:test')


def generate_auth(username: Union[str, bytes], password: Union[str, bytes]) -> bytes:
    if type(username) is str:
        username = username.encode('utf8')

    if type(password) is str:
        password = password.encode('utf8')

    return b'Basic ' + base64.b64encode(username + b':' + password)


@pytest.mark.parametrize(
    'url_usr,usr_endpoint,auth,auth_usr,pw,status',
    [('test', '', b'', b'', b'', '400 BAD REQUEST'),
     ('test', '', b'Basic', b'test', b'test', '200 OK'),
     ('test', '/activity', b'Basic', b'test', b'test', '200 OK'),
     ('test', '/activity/math', b'Basic', b'test', b'test', '200 OK'),
     ('test', '/log', b'Basic', b'test', b'test', '200 OK'),
     ('test', '/log/1', b'Basic', b'test', b'test', '200 OK'),
     ('test', '', b'Basic', b'test', b'test', '200 OK'),
     ('test', '', b'Basic', b'test', b'incorrect', '401 UNAUTHORIZED'),
     ('test', '', b'Basic', b'incorrect', b'test', '401 UNAUTHORIZED'),
     ('test', '', b'Basic', b'incorrect', b'also_incorrect', '401 UNAUTHORIZED'),
     ('other', '', b'Basic', b'test', b'test', '401 UNAUTHORIZED'),
     ('non_existent', '', b'Basic', b'test', b'test', '401 UNAUTHORIZED'),
     ('non_existent', '', b'Basic', b'non_existent', b'test', '401 UNAUTHORIZED'),
     ('test', '', b'other_method', b'test', b'test', '400 BAD REQUEST'),
     ]
)
def test_auth(client: FlaskClient, url_usr: str, usr_endpoint: str, auth: bytes, auth_usr: bytes, pw: bytes, status: str):
    endpoint = '/api/user/' + url_usr + usr_endpoint
    header = {'Authorization': auth + b' ' +
              base64.b64encode(auth_usr + b':' + pw)}

    response = client.get(endpoint, headers=header)
    assert response.status == status


def test_auth_garbage(client: FlaskClient):
    response = client.get(
        '/api/user/test', headers={'Authorization': 'pure_garbage'})
    assert response.status == '400 BAD REQUEST'


def test_credential_garbage(client: FlaskClient):
    response = client.get(
        '/api/user/test', headers={'Authorization': b'Basic ' + base64.b64encode(b'no_colon')})
    assert response.status == '400 BAD REQUEST'


def test_no_auth(client: FlaskClient):
    assert client.get('/api/').status == '200 OK'
    assert client.get('/api/user').status == '200 OK'
    assert client.get('/api/user/test').status == '401 UNAUTHORIZED'


def test_add_user(client: FlaskClient, app: Flask):
    payload = {
        'username': 'new',
        'name': 'Grace Hopper',
        'email': 'ghopper@test.com',
        'report_time': 92,
        'password': 'mark_one'
    }

    response: flask.Response = client.post('/api/user', json=payload)

    assert response.status == '201 CREATED'

    with app.app_context():
        assert response.headers['location'] == url_for(
            'api.user', username='new')
    assert client.get(response.headers['location'], headers={
                      'Authorization': generate_auth('new', 'mark_one')}).status == '200 OK'

    with app.app_context():
        db = get_db()
        row = db.execute('SELECT * FROM user WHERE username="new"').fetchone()
        assert row is not None
        assert row['username'] == payload['username']
        assert row['name'] == payload['name']
        assert row['email'] == payload['email']
        # This may not always work depending on the integer chosen
        assert row['report_time'] == payload['report_time']
        assert check_password_hash(row['password'], payload['password'])


@pytest.mark.parametrize(
    "key,",
    ['username', 'name', 'email', 'report_time', 'password', ]
)
def test_add_user_without_field(client: FlaskClient, app: Flask, key):
    payload = {
        'username': 'new',
        'name': 'Grace Hopper',
        'email': 'ghopper@test.com',
        'report_time': 92,
        'password': 'mark_one'
    }

    del payload[key]

    response: flask.Response = client.post('/api/user', json=payload)

    assert response.status == '400 BAD REQUEST'
    assert key in response.get_json()['description']


def test_add_user_bad_email(client: FlaskClient, app: Flask):
    payload = {
        'username': 'new',
        'name': 'Grace Hopper',
        'email': 'no_at_sign',
        'report_time': 92,
        'password': 'mark_one'
    }

    response: flask.Response = client.post('/api/user', json=payload)

    assert response.status == '400 BAD REQUEST'
    assert response.get_json(
    )['description'] == '400 Bad Request: Invalid email address.'


def test_non_int_report_time(client: FlaskClient, app: Flask):
    payload = {
        'username': 'new',
        'name': 'Grace Hopper',
        'email': 'ghopper@test.com',
        'report_time': "not_an_int",
        'password': 'mark_one'
    }

    response: flask.Response = client.post('/api/user', json=payload)

    assert response.status == '400 BAD REQUEST'
    assert response.get_json(
    )['description'] == '400 Bad Request: report_time must be integer.'


def test_no_json(client: FlaskClient, app: Flask):
    response: flask.Response = client.post('/api/user', json=None)

    assert response.status == '400 BAD REQUEST'
    assert 'JSON' in response.get_json()['description']


def test_user_exists(client: FlaskClient, app: Flask):
    payload = {
        'username': 'test',
        'name': 'Grace Hopper',
        'email': 'ghopper@test.com',
        'report_time': "not_an_int",
        'password': 'mark_one'
    }

    response: flask.Response = client.post('/api/user', json=payload)

    assert response.status == '409 CONFLICT'
    assert 'User already exists' in response.get_json()['description']


@pytest.mark.xfail
def test_get_non_existent_user(client: FlaskClient, app: Flask):
    # This would work if we didn't have authentication, but since we have
    # authentication, it returns a 401 UNAUTHORIZED error instead.
    assert client.get('/api/user/non_existent').status == '404 NOT FOUND'


@pytest.mark.parametrize(
    'key, value, status, message',
    [('name', 'Jones', '200 OK', ''),
     ('name', '', '400 BAD REQUEST', 'Name must be non-empty'),
     ('email', 'jones@gmail.com', '200 OK', ''),
     ('email', None, '400 BAD REQUEST', 'Email must be non-empty'),
     ('email', 'jones_no_at_sign', '400 BAD REQUEST', 'Invalid email address'),
     ('report_time', 500, '200 OK', ''),
     #('report_time', '500', '400 BAD REQUEST', 'integer'),
     ('report_time', 'asdf', '400 BAD REQUEST', 'integer'),
     ('report_time', None, '400 BAD REQUEST', 'Report time must be non-empty'),
     ('username', 'foo', '400 BAD REQUEST', 'Cannot change username'),
     ('id', 43536, '400 BAD REQUEST', 'Cannot change user id'),
     ]
)
def test_user_patch(client: FlaskClient, app: Flask, key: str, value, status: str, message: str):
    auth = {'Authorization': generate_auth('test', 'test')}

    payload = {key: value}

    response = client.patch('/api/user/test', json=payload, headers=auth)

    assert response.status == status
    if '200' not in status:
        assert message in response.get_json()['description']
    else:
        assert response.get_json()[key] == value

        with app.app_context():
            db = get_db()
            assert db.execute(
                'SELECT * FROM user WHERE username = "test"').fetchone()[key] == value


def test_successful_change_user_password(client: FlaskClient, app: Flask):
    auth = {'Authorization': generate_auth('test', 'test')}

    new_pw = 'new_test_password'
    payload = {'new_password': new_pw, 'password': 'test'}

    response = client.patch('/api/user/test', json=payload, headers=auth)

    assert response.status == '200 OK'

    with app.app_context():
        db = get_db()
        assert check_password_hash(db.execute(
            'SELECT password FROM user WHERE username = "test"').fetchone()[0], new_pw)
