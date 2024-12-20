from app import db
from sqlalchemy_serializer import SerializerMixin


class Quiz(db.Model, SerializerMixin):
    __tablename__ = "quiz"

    id = db.Column(db.Integer, primary_key=True)
    quiz_name = db.Column(db.String(100))
    # created_by_id = db.Column(db.Integer, db.ForeignKey('auth_users.id'), nullable=False)
    # created_by = db.relationship('auth_users')
    is_time_limit = db.Column(db.Boolean)
    timer = db.Column(db.Integer)
    no_question = db.Column(db.Integer)
    quiz_data = db.Column(db.String)
    play_times = db.Column(db.Integer)
    #rating = db.Column(db.Float(precision=2))
    #rate_voter = db.Column(db.Integer)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'), nullable=False)
    #tags = db.Column('tag', secondary=tags, lazy='subquery', backref=db.backref('pages', lazy=True))
    #tag = db.relationship('Tag', back_populates="tag")
    difficulty = db.Column(db.String)
    scoreboard = db.Column(db.String)
    detail = db.Column(db.String)
    is_deleted = db.Column(db.Boolean, default=False)

    def __init__(self, quiz_name, is_time_limit, timer, tag_id, difficulty, quiz_data, no_question, detail):
        self.quiz_name = quiz_name
        self.is_time_limit = is_time_limit
        self.timer = timer
        self.tag_id = tag_id
        self.difficulty = difficulty
        self.quiz_data = quiz_data
        self.no_question = no_question
        self.detail = detail
        self.play_times = 0
        self.scoreboard = ""

    def update(self, quiz_name, is_time_limit, timer, tag_id, difficulty, quiz_data, no_question, detail):
        self.quiz_name = quiz_name
        self.is_time_limit = is_time_limit
        self.timer = timer
        self.tag_id = tag_id
        self.difficulty = difficulty
        self.quiz_data = quiz_data
        self.no_question = no_question
        self.detail = detail
    
    def add_play_times(self):
        self.play_times += 1

    def get_data(self, var):
        if var == "is_time_limit":
            return self.is_time_limit
        if var == "is_deleted":
            return self.is_deleted
        if var == "difficulty":
            return self.difficulty
        if var == "tag_id":
            return self.tag_id
        return ""

class Tag(db.Model, SerializerMixin):
    __tablename__ = "tag"

    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String, unique=True)
    is_deleted = db.Column(db.Boolean, default=False)
    #quizs = db.relationship('Quiz', backref="Tag", lazy=True)

    def __init__(self, tag):
        self.tag = tag