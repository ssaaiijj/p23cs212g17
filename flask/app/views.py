import secrets
import string

from flask import (jsonify, render_template,
                   request, url_for, flash, redirect, abort, session)

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

    if current_user.is_authenticated:
        return redirect(url_for('play'))
    
    form = forms.Login()

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
    
    return render_template("login.html", form=form)


@app.route('/signup', methods=('GET', 'POST'))
def sign_up():
    form=forms.SignUp()
    # app.logger.debug(form.validate_on_submit())
    # app.logger.debug(form.errors)
    if form.validate_on_submit():
        result = request.form.to_dict()
        app.logger.debug(str(result))

        validated = True
        validated_dict = {}
        valid_keys = ['email', 'name', 'password']

        if form.email.errors:
            flash(form.email.errors)
            validated = False
            return redirect(url_for('sign_up'))
        
        if form.name.errors:
            flash(form.name.errors)
            validated = False
            return redirect(url_for('sign_up'))

        # validate the input
        for key in result:
            app.logger.debug(str(key)+": " + str(result[key]))
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                flash("Value Error")
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
            login_user(new_user)
            return redirect(url_for("play"))

    return render_template("sign_up.html", form=form)


@app.route('/play')
@login_required
def play():
    db_my_quiz = PrivateQuiz.query.filter(
        PrivateQuiz.created_by_id == current_user.id, PrivateQuiz.is_deleted == False
    )
    my_quiz = list(map(lambda x: x, db_my_quiz))
    db_other_quiz = PrivateQuiz.query.filter(
        PrivateQuiz.created_by_id != current_user.id, PrivateQuiz.is_deleted == False
    )
    other_quiz = list(map(lambda x: x, db_other_quiz))

    db_tag = Tag.query.filter_by(is_deleted=False).all()
    tag = list(map(lambda x: x, db_tag))

    return render_template("play.html", my_quiz=my_quiz, other_quiz=other_quiz, tag=tag)


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


@app.route('/db')
def db_connection():
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return '<h1>db works.</h1>'
    except Exception as e:
        return '<h1>db is broken.</h1>' + str(e)
    

@app.route('/api/username', methods=('GET', 'POST'))
def getName():

    if request.method == "POST":
        result = request.form.to_dict()
        user_data = AuthUser.query.get(result["user_id"])
        data = {
            "name": user_data.name
        }
        return jsonify(data)
    
    
@app.route('/quiz/<int:qid>')
@login_required
def quizinfo(qid):
    quiz = PrivateQuiz.query.get(qid)
    if not quiz or quiz.is_deleted:
        abort(404)

    user = AuthUser.query.get(quiz.created_by_id)
    tag = Tag.query.get(quiz.tag_id)

    return render_template("quizinfo.html", quiz=quiz, user=user, tag=tag)


@app.route('/leaderboard/<int:qid>')
def leaderboard(qid):

    quiz = PrivateQuiz.query.get(qid)

    if not quiz or quiz.is_deleted:
        abort(404)

    scoreboard = quiz.scoreboard
    scoreboard = eval(scoreboard)

    app.logger.debug("result", scoreboard)

    return render_template("leaderboard.html", scoreboard=scoreboard, qid=qid)


@app.route('/edit-profile', methods=('GET', 'POST'))
@login_required
def edit_profile():

    form = forms.EditProfile()

    if request.method == 'POST':
        # login code goes here
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        validated = True

        if form.email.errors:
            flash(form.email.errors)
            validated = False
        
        if form.name.errors:
            flash(form.name.errors)
            validated = False

        if not check_password_hash(current_user.password, password):
            validated = False
            flash('Password incorrect')

        if validated:

            validated_dict = {
                "name": name,
                "email": email,
            }

            if name != current_user.name:
                profile_pic = gen_avatar_url(email, name)
                validated_dict['avatar_url'] = profile_pic
            else:
                validated_dict['avatar_url'] = current_user.avatar_url

            user_data = AuthUser.query.get(current_user.id)
            if user_data.id == current_user.id:
                user_data.update(**validated_dict)
            db.session.commit()

            return redirect(url_for('play'))


    return render_template("edit_profile.html", form=form)


@app.route('/search', methods=('GET', 'POST'))
@login_required
def search():

    # https://www.reddit.com/r/flask/comments/usf6uy/how_can_i_apply_multiple_filters_to_the_result_of/
    # https://forum.jquery.com/portal/en/community/topic/input-field-validate-required-at-least-one-field

    if request.method == 'POST':
        result = request.form.to_dict()

        #app.logger.debug(type(list_filter))

        hasInput = False

        result = {key: value for (key, value) in result.items() if value}

        if result:
            hasInput = True

        if (hasInput):
            app.logger.debug(result)
            db_quiz = PrivateQuiz.query.filter_by(**result).all()
            quiz = list(map(lambda x: x, db_quiz))
            return render_template("search.html", quiz=quiz)
        else:
            flash("Search must has at least one input field")
            return redirect(url_for('play'))
        
    else:
        return redirect(url_for('play'))



@app.route('/result', methods=('GET', 'POST'))
@login_required
def result():

    if request.method == 'POST':
        result = request.form.to_dict()
        qid = result["q_id"]

        quiz = PrivateQuiz.query.get(qid)
        no_ques = quiz.no_question
        quiz_data = quiz.quiz_data
        quiz_data = eval(quiz_data)

        list_ans = dict()
        list_choose = dict()

        for no_q in quiz_data:
            list_ans[int(no_q)] = int(quiz_data[no_q]["answer"])

        for key in result:
            if key == "q_id":
                continue

            list_key = key.split("-")

            if list_key[0] == "answer":
                list_choose[int(list_key[1])] = int(result[key])

        all_len = len(list_choose)
        i = 0
        score = 0

        while (i < all_len):
            if list_ans[i] == list_choose[i]:
                score += 1
            i += 1

        scoreboard = quiz.scoreboard

        if scoreboard:
            scoreboard = eval(scoreboard)
            all_score = len(scoreboard)

            max_p = True
            updateRank = False

            if all_score < 5:
                max_p = False
            
            for i in range(all_score):
                rank = scoreboard[i]
                if rank[0] == current_user.id:
                    if score > rank[1]:
                        rank[1] = score
                        scoreboard[i] = rank
                        updateRank = True
                        break
                else:
                    if score > rank[1]:
                        if i == 4:
                            rank = [current_user.id, score]
                            scoreboard[i] = rank
                            updateRank = True
                            break
                        else:
                            for p in range(3, i - 1, -1):
                                rank_move = scoreboard[p]
                                scoreboard[p + 1] = rank_move
                            rank = [current_user.id, score]
                            scoreboard[i] = rank
                            updateRank = True
                            break
                
                if (not max_p and not updateRank):
                    scoreboard[i + 1] = [current_user.id, score]

            quiz.scoreboard = str(scoreboard)
            db.session.commit()

        else:
            scoreboard = {0: [current_user.id, score]}
            scoreboard = str(scoreboard)
            quiz.scoreboard = scoreboard
            db.session.commit()

        app.logger.debug("scoreboard", scoreboard)

    return render_template("result.html", score=score, no_ques=no_ques, qid=qid)

@app.route('/create-tag', methods=('GET', 'POST'))
def create_tag():

    if current_user.is_authenticated:
        if not current_user.is_admin:
            abort(404)
            #pass
    else:
        abort(404)

    if request.method == 'POST':
        tag = request.form.get('tag').capitalize()

        tag_db = Tag.query.filter_by(tag=tag).first()

        if tag_db and not tag_db.is_deleted:
            flash("already have " + tag + " tag")
            return redirect(url_for('admin'))
        
        if tag_db and tag_db.is_deleted:
            tag_db.tag_db.is_deleted = False
        else:
            db.session.add(Tag(tag=tag))

        db.session.commit()
        return redirect(url_for('admin'))

    else:
        return redirect(url_for('play'))


@app.route('/tag/<int:tid>/edit/', methods=('GET', 'POST'))
def edit_tag(tid):

    if current_user.is_authenticated:
        if not current_user.is_admin:
            abort(404)
            #pass
    else:
        abort(404)

    tag_db = Tag.query.get(tid)

    if request.method == 'POST' and tag_db:
        tag_db.tag = request.form.get('tag').capitalize()
        db.session.commit()
        return redirect(url_for("admin"))

    return render_template("tag_edit.html", tid=tid, tag=tag_db)


@app.route('/tag/<int:tid>/del/')
def del_tag(tid):

    if current_user.is_authenticated:
        if not current_user.is_admin:
            abort(404)
            #pass
    else:
        abort(404)

    tag_db = Tag.query.get(tid)

    if not tag_db.is_deleted:
        app.logger.debug("del tag")
        tag_db.is_deleted = True
        db.session.commit()
    
    return redirect(url_for("admin"))


@app.route('/quiz/<int:qid>/play/')
@login_required
def playmode(qid):

    quiz = PrivateQuiz.query.get(qid)

    timer = int(quiz.timer)

    if not quiz or quiz.is_deleted:
        abort(404)
    
    question = quiz.quiz_data
    question = eval(question)

    return render_template("playmode.html", question=question, qid=qid, timer=timer)

@app.route('/quiz/<int:qid>/del/', methods=('GET', 'POST'))
@login_required
def del_quiz(qid):
    quiz_c = PrivateQuiz.query.get(qid)

    if not quiz_c or quiz_c.is_deleted:
        abort(404)

    if current_user.id != quiz_c.created_by_id and not current_user.is_admin:
        abort(403)

    quiz_c.is_deleted = True
    db.session.commit()
    return redirect(url_for('play'))

@app.route('/quiz/<int:qid>/edit/', methods=('GET', 'POST'))
@login_required
def edit_quiz(qid):

    form = forms.Quiz()
    quiz_c = PrivateQuiz.query.get(qid)

    if not quiz_c or quiz_c.is_deleted:
        abort(404)

    if current_user.id != quiz_c.created_by_id and not current_user.is_admin:
        abort(403)

    db_tag = Tag.query.all()
    tag = list(map(lambda x: x.to_dict(), db_tag))
    tag_s = Tag.query.get(quiz_c.tag_id)

    question = quiz_c.quiz_data
    question = eval(question)

    if request.method == 'POST':
        result = request.form.to_dict()

        quiz = dict()
        list_que_key = []       

        for key in result:
            if "questions" in key:
                list_key = key.split("-")
                list_que_key.append([key, list_key])
                continue

            if key == "csrf_token":
                continue

            quiz[key] = result[key]

        if quiz["timer"] == "None":
            quiz["timer"] = 0
            quiz["is_time_limit"] = False
        else:
            quiz["is_time_limit"] = True

        question = dict()

        app.logger.debug(list_que_key)

        for pair_key in list_que_key:
            no_q = pair_key[1][1]

            if no_q not in question:
                question[no_q] = dict()

            if pair_key[1][2] == "answer":
                question[no_q]["answer"] = result[pair_key[0]]
                continue

            if pair_key[1][2] == "question":
                app.logger.debug(pair_key[0])
                question[no_q]["question"] = result[pair_key[0]]
                continue

            if pair_key[1][2] == "choices":
                if "choices" in question[no_q]:
                    question[no_q]["choices"].append(result[pair_key[0]])
                else:
                    question[no_q]["choices"] = [result[pair_key[0]]]

        quiz["questions"] = question

        app.logger.debug(quiz)

        quiz_c.update(
            quiz_name=quiz['quiz_name'], is_time_limit=quiz["is_time_limit"], timer=quiz["timer"],
            tag_id=quiz["tag"], difficulty=quiz["difficulty"], quiz_data=str(quiz['questions']),
            no_question=quiz["quiz-no-q"]
        )
        db.session.commit()
        return redirect(url_for("play"))

    return render_template("edit_quiz.html", question=question, quiz=quiz_c, form=form, tag=tag, tag_s=tag_s)


@app.route('/create', methods=('GET', 'POST'))
@login_required
def create():

    form = forms.Quiz()
    db_tag = Tag.query.all()
    tag = list(map(lambda x: x.to_dict(), db_tag))

    if request.method == 'POST':
        result = request.form.to_dict()

        #list_want = []

        quiz = dict()
        list_que_key = []       

        for key in result:
            if "questions" in key:
                list_key = key.split("-")
                list_que_key.append([key, list_key])
                continue

            if key == "csrf_token":
                continue

            quiz[key] = result[key]

        if quiz["timer"] == "None":
            quiz["timer"] = 0
            quiz["is_time_limit"] = False
        else:
            quiz["is_time_limit"] = True

        question = dict()

        app.logger.debug(list_que_key)

        for pair_key in list_que_key:
            no_q = pair_key[1][1]

            if no_q not in question:
                question[no_q] = dict()

            if pair_key[1][2] == "answer":
                question[no_q]["answer"] = result[pair_key[0]]
                continue

            if pair_key[1][2] == "question":
                app.logger.debug(pair_key[0])
                question[no_q]["question"] = result[pair_key[0]]
                continue

            if pair_key[1][2] == "choices":
                if "choices" in question[no_q]:
                    question[no_q]["choices"].append(result[pair_key[0]])
                else:
                    question[no_q]["choices"] = [result[pair_key[0]]]

        quiz["questions"] = question

        app.logger.debug(quiz)

        db.session.add(PrivateQuiz(
            quiz_name=quiz['quiz_name'], is_time_limit=quiz["is_time_limit"], timer=quiz["timer"],
            tag_id=quiz["tag"], difficulty=quiz["difficulty"], quiz_data=str(quiz['questions']), own_id=current_user.id,
            no_question=quiz["quiz-no-q"]
        ))
        db.session.commit()

        return redirect(url_for('play'))



    return render_template("create.html", form=form, tag=tag)



@app.route('/qwerty')
def admin():
    if current_user.is_authenticated:
        if not current_user.is_admin:
            abort(404)
            #pass
    else:
        abort(404)

    db_tag = Tag.query.filter_by(is_deleted=False).all()
    db_quiz = PrivateQuiz.query.all()
    tag = list(map(lambda x: x, db_tag))
    quiz = list(map(lambda x: x, db_quiz))

    return render_template("admin.html", tag=tag, quiz=quiz)

