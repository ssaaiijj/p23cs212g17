from flask_login import UserMixin
from sqlalchemy_serializer import SerializerMixin

from app import db
from app.models.quiz import Quiz

class AuthUser(db.Model, UserMixin):
    __tablename__ = "auth_users"
    # primary keys are required by SQLAlchemy
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(1000))
    password = db.Column(db.String(100))
    avatar_url = db.Column(db.String(250))
    is_admin = db.Column(db.Boolean)
    my_quizs = db.relationship('Quiz', backref='auth_users', lazy=True)

    def __init__(self, email, name, password, avatar_url, is_admin):
        self.email = email
        self.name = name
        self.password = password
        self.avatar_url = avatar_url
        self.is_admin = is_admin

    def update(self, email, name, avatar_url):
        self.email = email
        self.name = name
        self.avatar_url = avatar_url

class PrivateQuiz(Quiz, UserMixin, SerializerMixin):
    created_by_id = db.Column(db.Integer, db.ForeignKey('auth_users.id'))

    def __init__(self, quiz_name, is_time_limit, timer, tag_id, difficulty, quiz_data, no_question, own_id):
        super().__init__(quiz_name, is_time_limit, timer, tag_id, difficulty, quiz_data, no_question)
        self.created_by_id = own_id