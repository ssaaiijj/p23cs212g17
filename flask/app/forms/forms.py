from flask_wtf import FlaskForm
from wtforms import (StringField, EmailField, FieldList, PasswordField, 
                     IntegerField, FormField, RadioField, SelectField, TextAreaField)
from wtforms.validators import InputRequired, Length, Email

class Login(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(message=""), Length(max=50), Email("Invalid Email")])
    password = PasswordField('Password', validators=[InputRequired(message="")])

class SignUp(FlaskForm):
    name = StringField('Name', validators=[InputRequired(message=""), Length(min=2, max=40, message="Name must be longer than 1 letter.")])
    email = EmailField('Email', validators=[InputRequired(message=""), Length(max=50), Email("Invalid Email")])
    password = PasswordField('Password', validators=[InputRequired(message="")])

class EditProfile(FlaskForm):
    name = StringField('Name', validators=[InputRequired(message=""), Length(min=2, max=40, message="Name must be longer than 1 letter.")])
    email = EmailField('Email', validators=[InputRequired(message=""), Length(max=50), Email("Invalid Email")])
    password = PasswordField('Confirm Password', validators=[InputRequired(message="")])

class Choice(FlaskForm):
    choice = StringField('choice')

class Question(FlaskForm):
    no_question = IntegerField('No question', validators=[InputRequired(message="")])
    question = StringField("Question", validators=[InputRequired(message="")])
    choices = FieldList(FormField(Choice), min_entries=2, max_entries=4, validators=[InputRequired(message="")])
    answer = RadioField('Answer', validators=[InputRequired(message="")])

class Quiz(FlaskForm):
    quiz_name = StringField('Quiz Name', validators=[InputRequired(message="")])
    tag = SelectField('Tag', validators=[InputRequired(message="")])
    difficulty = SelectField('Difficulty', choices=[('easy', 'Easy'), ('normal', 'Normal'), ('hard', 'Hard')], validators=[InputRequired(message="")])
    timer = SelectField('Timer', validators=[InputRequired(message="")])
    questions = FieldList(FormField(Question), min_entries=1)
    detail = TextAreaField("Quiz Detail", validators=[InputRequired(message="")])