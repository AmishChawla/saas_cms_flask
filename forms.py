from wtforms import StringField, PasswordField, SubmitField, validators, SelectField
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
import email_validator

class UploadForm(FlaskForm):
    files = FileField('Upload PDF Files', validators=[FileRequired()])


class LoginForm(FlaskForm):
    email = StringField('Email')
    password = PasswordField('Password')
    submit = SubmitField('Log In')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[validators.Length(min=4, max=25), validators.DataRequired()])
    email = StringField('Email', validators=[validators.Email(), validators.DataRequired()])
    password = PasswordField('Password', validators=[
        validators.DataRequired(),
        validators.Length(min=6),
        validators.Regexp(
            regex="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]",
            message="Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character."
        )
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        validators.EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Register')


class AdminAddUserForm(FlaskForm):
    username = StringField('Username', validators=[validators.Length(min=4, max=25), validators.DataRequired()])
    email = StringField('Email', validators=[validators.Email(), validators.DataRequired()])
    password = PasswordField('Password', validators=[
        validators.DataRequired(),
        validators.Length(min=6),
        validators.Regexp(
            regex="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]",
            message="Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character."
        )
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        validators.EqualTo('password', message='Passwords must match.')
    ])
    role = SelectField('Select Role :', choices=['user', 'admin'])
    submit = SubmitField('Add')


class UserPasswordUpdateForm(FlaskForm):

    current_password = PasswordField('Password', validators=[
        validators.DataRequired(),
        validators.Length(min=6),
        validators.Regexp(
            regex="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]",
            message="Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character."
        )
    ])
    new_password = PasswordField('Password', validators=[
        validators.DataRequired(),
        validators.Length(min=6),
        validators.Regexp(
            regex="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]",
            message="Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character."
        )
    ])
    confirm_new_password = PasswordField('Confirm Password', validators=[
        validators.EqualTo('new_password', message='Passwords must match.')
    ])
    submit = SubmitField('Update Password')


class ForgetPasword(FlaskForm):
    email = StringField('Email')
    submit = SubmitField('Submit')


class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('Password', validators=[
        validators.DataRequired(),
        validators.Length(min=6),
        validators.Regexp(
            regex="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]",
            message="Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character."
        )
    ])
    confirm_new_password = PasswordField('Confirm Password', validators=[
        validators.EqualTo('new_password', message='Passwords must match.')
    ])
    submit = SubmitField('Submit')