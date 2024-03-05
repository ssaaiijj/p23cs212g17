from flask.cli import FlaskGroup
from werkzeug.security import generate_password_hash
from app import app, db
from app.models.authuser import AuthUser, PrivateQuiz
from app.models.quiz import Tag
from datetime import datetime, timezone

cli = FlaskGroup(app)

@cli.command("create_db")
def create_db():
    db.drop_all() # debug mode
    db.create_all()
    db.session.commit()

@cli.command("seed_db")
def seed_db():
    email_ad = "flask@204212.com"
    
    if (not AuthUser.query.filter_by(email=email_ad).first()):
        admin = AuthUser(email=email_ad, name='สมชาย ทรงแบด',
                            password=generate_password_hash('1234',
                                                            method='sha256'),
                            avatar_url='https://ui-avatars.com/api/?name=\
สมชาย+ทรงแบด&background=83ee03&color=fff', is_admin=True)     
        db.session.add(admin)

    list_tags = ["Game", "Education", "Sport", "LifeStyle", "Movie", "Code"]

    for tag in list_tags:
        db.session.add(Tag(tag=tag))

    db.session.commit()

if __name__ == "__main__":
    cli()