import os
import tempfile
from flask.app import Flask

import pytest
import werkzeug
from DailyDataServer import create_app
from DailyDataServer.db import get_db, init_db

import flask
from flask.testing import FlaskClient

with open(os.path.join(os.path.dirname(__file__), 'data.sql'), 'rb') as f:
    _data_sql = f.read().decode('utf8')


@pytest.fixture
def app() -> Flask:
    db_fd, db_path = tempfile.mkstemp()

    app = create_app({
        'TESTING': True,
        'DATABASE': db_path,
        'SERVER_NAME': '127.0.0.1'
    })

    with app.app_context():
        init_db()
        get_db().executescript(_data_sql)

    yield app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app) -> FlaskClient:
    return app.test_client()


@pytest.fixture
def runner(app) -> flask.Flask:
    return app.test_cli_runner()
