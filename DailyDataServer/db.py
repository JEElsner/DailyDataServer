import sqlite3

import click
from flask import current_app, g
from flask.cli import with_appcontext


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(reset_db_command)


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

        return g.db


def init_db():
    db = get_db()

    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))


def drop_db_tables():
    db = get_db()

    try:
        db.executescript('DROP TABLE user;'
                         'DROP TABLE activity;'
                         'DROP TABLE timelog;')
        db.commit()
    except:
        pass


@click.command('init-db')
@with_appcontext
def init_db_command():
    """Create the tables if they do not already exist."""
    init_db()
    click.echo('Initialized the database.')


@click.command('reset-db')
@with_appcontext
def reset_db_command():
    if click.confirm('Are you sure?'):
        drop_db_tables()
        init_db()

        click.echo('Reset the database.')
    else:
        click.echo('Aborted reseting the database.')


def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()
