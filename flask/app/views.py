from flask import (jsonify, render_template,
                   request, url_for, flash, redirect)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse

from sqlalchemy.sql import text
from flask_login import login_user, login_required, logout_user, current_user

from app import app
from app import db
from app import login_manager
from app import oauth


@app.route('/')
def home():
    return "Flask says 'Hello world!'"


@app.route('/crash')
def crash():
    return 1/0


@app.route('/db')
def db_connection():
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return '<h1>db works.</h1>'
    except Exception as e:
        return '<h1>db is broken.</h1>' + str(e)