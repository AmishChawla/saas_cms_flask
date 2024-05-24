from wtforms import StringField, IntegerField, PasswordField, SubmitField, validators, SelectField, BooleanField, \
    TextAreaField
from flask_wtf import FlaskForm

from flask_wtf.file import FileField, FileRequired, FileAllowed

import email_validator
from wtforms.validators import DataRequired, Optional


class UploadForm(FlaskForm):
    ALLOWED_EXTENSIONS = {'pdf', 'docx'}

    files = FileField('Upload PDF Files', validators=[
        FileRequired(),

        FileAllowed(ALLOWED_EXTENSIONS, 'Only PDF files are allowed.'),
        FileAllowed(ALLOWED_EXTENSIONS, 'Only pdf and docx files are allowed.')
    ])


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


class AdminRegisterForm(FlaskForm):
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


class CompanyRegisterForm(FlaskForm):
    name = StringField('Name')
    location = StringField('Location')
    submit = SubmitField('Submit')


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


class AdminEditUserForm(FlaskForm):
    username = StringField('Username', validators=[validators.Length(min=4, max=25), validators.DataRequired()])

    role = SelectField('Select Role :', choices=['user', 'admin'])
    status = SelectField('Select Status :', choices=['active', 'block'])
    submit = SubmitField('Save')


class AdminAddServiceForm(FlaskForm):
    name = StringField('name', validators=[validators.DataRequired()])
    description = StringField('description', validators=[validators.DataRequired()])
    submit = SubmitField('Add Service')


class AdminEditServiceForm(FlaskForm):
    name = StringField('Name', validators=[validators.DataRequired()])
    description = StringField('Description', validators=[validators.DataRequired()])
    submit = SubmitField('Update Service')


class AdminEditCompanyForm(FlaskForm):
    name = StringField('Name')
    location = StringField('Location')
    submit = SubmitField('Update Company')


class UserEditUserForm(FlaskForm):
    profile_picture = FileField('Profile Picture', render_kw={"id": "profile_picture_input", "style": "display: none;"})
    username = StringField('Username', validators=[validators.Length(min=4, max=25), validators.DataRequired()], render_kw={"readonly": True})
    email = StringField('Email', validators=[validators.Email(), validators.DataRequired()], render_kw={"readonly": True})
    submit = SubmitField('Save')

class EmailFunctionalityForm(FlaskForm):
    smtp_server = StringField('SMTP Server')
    smtp_port = IntegerField('SMTP Port')
    smtp_username = StringField('SMTP Username')
    smtp_password = StringField('SMTP Password')
    sender_email = StringField('Sender Email')
    submit = SubmitField('Save')


class ServiceForm(FlaskForm):
    submit = SubmitField('Save')


class AddPlan(FlaskForm):
    name = StringField('Plan Name', validators=[validators.DataRequired()])
    duration = StringField('Duration (Months)', validators=[validators.DataRequired()])
    fees = IntegerField('Fees', validators=[Optional()])
    is_free =  BooleanField('Free')
    unlimited_resume_parsing = BooleanField('Unlimited')
    num_resume_parsing = StringField('Number of Resume Parsings', validators=[Optional()])
    plan_details = TextAreaField('Plan Details', render_kw={'rows': 30, 'cols': 30, 'placeholder': 'Enter plan details here...'})
    submit = SubmitField('Add Plan')


class AddPost(FlaskForm):
    title = StringField('Post title', validators=[validators.DataRequired()])
    category = SelectField('Category', coerce=int, validators=[DataRequired()], default='Select Category')
    content = TextAreaField('Content', render_kw={'rows': 30, 'cols': 30, 'placeholder': 'Enter Content here...'})
    submit = SubmitField('Add Post')

class AddCategory(FlaskForm):
    category = StringField('Category title', validators=[validators.DataRequired()])
    submit = SubmitField('Add Category')


class AddSubcategory(FlaskForm):
    subcategory = StringField('Subcategory title', validators=[validators.DataRequired()])
    category = SelectField('Category', coerce=int, validators=[DataRequired()], default='Select Category')
    submit = SubmitField('Add Subcategory')

class AdminUpdatePost(FlaskForm):
    title = StringField('Post title', validators=[validators.DataRequired()])
    content = TextAreaField('Content', render_kw={'rows': 30, 'cols': 30, 'placeholder': 'Enter Content here...'})
    submit = SubmitField('Update Post')


class CreateEmailTemplate(FlaskForm):
    name = StringField('Name', validators=[validators.DataRequired()])
    subject = StringField('Subject', validators=[validators.DataRequired()])
    content = TextAreaField('Write Email here ...', render_kw={'rows': 10, 'cols': 30, 'placeholder': 'Enter Content here...'})
    submit = SubmitField('Create Template')


class UpdateEmailTemplate(FlaskForm):
    name = StringField('Name', validators=[validators.DataRequired()])
    subject = StringField('Subject', validators=[validators.DataRequired()])
    content = TextAreaField('Write Email here ...', render_kw={'rows': 10, 'cols': 30, 'placeholder': 'Enter Content here...'})
    submit = SubmitField('Update Template')


class SendEmail(FlaskForm):
    to = StringField('To', validators=[validators.DataRequired()])
    subject = StringField('Subject', validators=[validators.DataRequired()])
    content = TextAreaField('Content', render_kw={'rows': 10, 'cols': 30, 'placeholder': 'Enter Content here...'})
    submit = SubmitField('Send Mail')