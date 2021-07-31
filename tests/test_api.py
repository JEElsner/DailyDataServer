import pytest

from DailyDataServer.db import get_db

import base64
import flask
from flask.testing import FlaskClient
import werkzeug

BASIC_CREDENTIAL = base64.b64encode(b'test:test')


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
