from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, EqualTo, ValidationError
from flask_login import UserMixin
from .models import User


class LoginForm(FlaskForm, UserMixin):
    email = StringField('Username (email)', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')


def validate_email(email):
    user = User.query.filter_by(email=email.data).first()
    if user is not None:
        raise ValidationError('Email has previously registered')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    password2 = PasswordField('Repeat Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    # flask-wtf takes validate_<field_name> as custom validators
    # so the below validator gets invoked on username
