import secrets
import string

from flask import (jsonify, render_template,
                   request, url_for, flash, redirect, abort)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse

from sqlalchemy.sql import text
from flask_login import login_user, login_required, logout_user, current_user
from markupsafe import escape

from app import app
from app import db
from app import login_manager
from app.models.authuser import AuthUser, PrivateQuiz
from app.models.quiz import Tag
from app.forms import forms
from app import oauth


@app.route('/', methods=('GET', 'POST'))
def home():

    if request.method == 'POST':
        # login code goes here
        email = request.form.get('email')
        password = request.form.get('password')

        user = AuthUser.query.filter_by(email=email).first()
 
        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the
        # hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            # if the user doesn't exist or password is wrong, reload the page
            return redirect(url_for('home'))

        # if the above check passes, then we know the user has the right
        # credentials
        login_user(user)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('play')
        return redirect(next_page)
    
    return app.send_static_file("login.html")


@app.route('/signup', methods=('GET', 'POST'))
def sign_up():
    form=forms.SignUp()
    app.logger.debug(form.validate_on_submit())
    app.logger.debug(form.errors)
    if form.validate_on_submit():
        result = request.form.to_dict()
        app.logger.debug(str(result))

        validated = True
        validated_dict = {}
        valid_keys = ['email', 'name', 'password']

        # validate the input
        for key in result:
            app.logger.debug(str(key)+": " + str(result[key]))
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value
            # code to validate and add user to database goes here
        app.logger.debug("validation done")
        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            email = validated_dict['email']
            name = validated_dict['name']
            password = validated_dict['password']
            # if this returns a user, then the email already exists in database
            user = AuthUser.query.filter_by(email=email).first()

            if user:
                # if a user is found, we want to redirect back to signup
                # page so user can try again
                flash('Email address already exists')
                return redirect(url_for('sign_up'))

            # create a new user with the form data. Hash the password so
            # the plaintext version isn't saved.
            app.logger.debug("preparing to add")
            avatar_url = gen_avatar_url(email, name)
            new_user = AuthUser(email=email, name=name,
                                password=generate_password_hash(
                                    password, method='sha256'),
                                avatar_url=avatar_url, is_admin=False)
            # add the new user to the database
            db.session.add(new_user)
            db.session.commit()

        return redirect(url_for('home'))

    return render_template("sign_up.html",form=form)


@app.route('/play')
@login_required
def play():
    db_my_quiz = PrivateQuiz.query.filter(
        PrivateQuiz.created_by_id == current_user.id
    )
    my_quiz = list(map(lambda x: x.to_dict(), db_my_quiz))
    db_other_quiz = PrivateQuiz.query.filter(
        PrivateQuiz.created_by_id != current_user.id
    )
    other_quiz = list(map(lambda x: x.to_dict(), db_other_quiz))

    return render_template("play.html", my_quiz=my_quiz, other_quiz=other_quiz)


@app.route('/create-quiz')
def create_quiz():
    return render_template("create_quiz.html")


@app.route('/google/')
def google():

    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

   # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    app.logger.debug(str(token))
    userinfo = token['userinfo']
    app.logger.debug(" Google User " + str(userinfo))
    email = userinfo['email']
    user = AuthUser.query.filter_by(email=email).first()

    if not user:
        name = userinfo.get('given_name','') + " " + userinfo.get('family_name','')
        random_pass_len = 8
        password = ''.join(secrets.choice(string.ascii_uppercase + string.digits)
                          for i in range(random_pass_len))
        picture = userinfo['picture']
        new_user = AuthUser(email=email, name=name,
                           password=generate_password_hash(
                               password, method='sha256'),
                           avatar_url=picture, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        user = AuthUser.query.filter_by(email=email).first()
    login_user(user)
    return redirect('/play')


@app.route('/facebook/')
def facebook():
   
    # Facebook Oauth Config
    oauth.register(
        name='facebook',
        client_id=app.config['FACEBOOK_CLIENT_ID'],
        client_secret=app.config['FACEBOOK_CLIENT_SECRET'],
        access_token_url='https://graph.facebook.com/oauth/access_token',
        access_token_params=None,
        authorize_url='https://www.facebook.com/dialog/oauth',
        authorize_params=None,
        api_base_url='https://graph.facebook.com/',
        client_kwargs={'scope': 'email'},
    )
    redirect_uri = url_for('facebook_auth', _external=True)
    return oauth.facebook.authorize_redirect(redirect_uri)
 
 
@app.route('/facebook/auth/')
def facebook_auth():
    token = oauth.facebook.authorize_access_token()
    app.logger.debug(str(token))
    resp = oauth.facebook.get(
        'https://graph.facebook.com/me?fields=id,name,email,picture{url}')
    profile = resp.json()
    app.logger.debug("Facebook User ", profile)
    user = AuthUser.query.filter_by(email=profile['email']).first()
    if not user:
        name = profile.get('name')
        random_pass_len = 8
        password = ''.join(secrets.choice(string.ascii_uppercase + string.digits)
                          for i in range(random_pass_len))
        picture = profile['picture']['data']['url']
        new_user = AuthUser(email=profile['email'], name=name,
                           password=generate_password_hash(
                               password, method='sha256'),
                           avatar_url=picture, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        user = AuthUser.query.filter_by(email=profile['email']).first()
    login_user(user)
    return redirect('/play')


def gen_avatar_url(email, name):
    bgcolor = generate_password_hash(email, method='sha256')[-6:]
    color = hex(int('0xffffff', 0) -
                int('0x'+bgcolor, 0)).replace('0x', '')
    lname = ''
    temp = name.split()
    fname = temp[0][0]
    if len(temp) > 1:
        lname = temp[1][0]

    avatar_url = "https://ui-avatars.com/api/?name=" + \
        fname + "+" + lname + "&background=" + \
        bgcolor + "&color=" + color
    return avatar_url


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our
    # user table, use it in the query for the user
    return AuthUser.query.get(int(user_id))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/crash')
def crash():
    return 1/0


@app.route('/create')
def createOverview():
    return app.send_static_file('CreateQuizOver.html')


@app.route('/createQuestion')
def createQuestion():
    return app.send_static_file('CreateQuizQues.html')


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


@app.route('/test', methods=('GET', 'POST'))
def test():

    form = forms.Quiz()

    if request.method == 'POST':
        result = request.form.to_dict()
        return jsonify(result)

    return render_template("test.html", form=form)



@app.route('/qwerty')
def admin():
    if current_user.is_authenticated:
        if not current_user.is_admin:
            abort(404)
            #pass
    else:
        abort(404)

    db_tag = Tag.query.all()
    db_quiz = PrivateQuiz.query.all()
    tag = list(map(lambda x: x.to_dict(), db_tag))
    quiz = list(map(lambda x: x.to_dict(), db_quiz))

    return render_template("admin.html", tag=tag, quiz=quiz)

