from app import db
from sqlalchemy_serializer import SerializerMixin


class Quiz(db.Model, SerializerMixin):
    __tablename__ = "quiz"

    id = db.Column(db.Integer, primary_key=True)
    quiz_name = db.Column(db.String(100))
    # created_by_id = db.Column(db.Integer, db.ForeignKey('auth_users.id'), nullable=False)
    # created_by = db.relationship('auth_users')
    is_time_limit = db.Column(db.Boolean)
    no_question = db.Column(db.Integer)
    quiz_data = db.Column(db.PickleType)
    play_times = db.Column(db.Integer)
    rating = db.Column(db.Float)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'), nullable=False)
    #tags = db.Column('tag', secondary=tags, lazy='subquery', backref=db.backref('pages', lazy=True))
    difficulty = db.Column(db.String)
    scoreboard = db.Column(db.PickleType)
    deleted = db.Column(db.Boolean, default=False)

    def __init__(self, quiz_name, is_time_limit, tag, difficulty):
        self.quiz_name = quiz_name
        self.is_time_limit = is_time_limit
        self.tag = tag
        self.difficulty = difficulty
        self.play_times = 0
    
    def add_play_times(self):
        self.play_times += 1

class Tag(db.Model, SerializerMixin):
    __tablename__ = "tag"

    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String)
    quizs = db.relationship('Quiz', backref='tag', lazy=True)

    def __init__(self, tag):
        self.tag = tag