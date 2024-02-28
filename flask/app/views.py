from flask import (jsonify, render_template,
                   request, url_for, flash, redirect)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse

from sqlalchemy.sql import text
from flask_login import login_user, login_required, logout_user, current_user

from app import app
from app import db


@app.route('/', methods=('GET', 'POST'))
def home():
    return app.send_static_file("login.html")


@app.route('/signup', methods=('GET', 'POST'))
def sign_up():
    return app.send_static_file("sign_up.html")


@app.route('/play')
def play():
    return app.send_static_file("play.html")


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
    
@app.route('/quizinfo')
def quizinfo():
    return app.send_static_file("quizinfo.html")

@app.route('/leaderboard')
def leaderboard():
    return app.send_static_file("leaderboard.html")


@app.route('/result')
def result():
    return app.send_static_file("result.html")


@app.route('/playmode')
def playmode():
    return app.send_static_file("playmode.html")