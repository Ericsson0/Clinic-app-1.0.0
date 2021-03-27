from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flaskblog.models import User

class DetailForm(FlaskForm):
    Symptom = StringField('Symptom', validators=[DataRequired(), Length(min=2, max=500)]) 
    Check_result = StringField('Check_result', validators=[DataRequired(), Length(min=2, max=500)])
    Preliminary_treatment_plan = StringField('Preliminary_treatment_plan', validators=[DataRequired(), Length(min=2, max=500)])
    tag = StringField('tag', validators=[DataRequired(), Length(min=2, max=100)]) 
    submit = SubmitField('添加') 

class MedicineForm(FlaskForm):
    Vendor = StringField('Vendor', validators=[DataRequired(), Length(min=2, max=200)]) 
    Quantity = StringField('Quantity', validators=[DataRequired(), Length(min=2, max=5)]) 
    Medicine_name = StringField('Medicine', validators=[DataRequired(), Length(min=2, max=200)]) 
    Deadline = StringField('Deadline', validators=[DataRequired(), Length(min=2, max=20)]) 
    Price = StringField('Price', validators=[DataRequired(), Length(min=2, max=200)])
    How_to_use = StringField('How_to_use', validators=[DataRequired(), Length(min=2, max=100)])
    submit = SubmitField('添加') 

class RegistrationForm(FlaskForm):
    name = StringField('Name',
                           validators=[DataRequired(), Length(min=2, max=20)])
    IDcard = StringField('card', validators=[DataRequired(), Length(min=18, max=20)]) 
    number = StringField('number', validators=[DataRequired(), Length(min=11, max=11)]) 
    gender = SelectField('gender', choices=[('女', '女'), ('男', '男')])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    department = StringField('department',
                        validators=[DataRequired(), Length(min=2, max=30)])  
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('注册')

    def validate_username(self, name):
        user = User.query.filter_by(name=name.data).first()
        if user:
            raise ValidationError('That name is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    name = StringField('name',
                        validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('登录')

class PatientForm(FlaskForm):
    name = StringField('name', validators=[DataRequired(), Length(min=2, max=20)]) 
    number = StringField('number', validators=[DataRequired(), Length(min=11, max=11)]) 
    gender = SelectField('gender', choices=[('女', '女'), ('男', '男')]) 
    birth = StringField('birth', validators=[DataRequired(), Length(min=10, max=10)])
    IDcard = StringField('IDcard', validators=[DataRequired(), Length(min=18, max=20)])  
    location = StringField('location', validators=[DataRequired(), Length(min=2, max=20)])  
    submit = SubmitField('添加')  
 
class AddWorkLogForm(FlaskForm):
    title = StringField('title', validators=[DataRequired(), Length(min=2, max=200)]) 
    body = StringField('body', validators=[DataRequired(), Length(min=2, max=200)]) 
    tag = StringField('tag', validators=[DataRequired(), Length(min=2, max=200)]) 
    submit = SubmitField('添加')

class UpdateDoctorForm(FlaskForm):
    name = StringField('Name',
                           validators=[DataRequired(), Length(min=2, max=20)])
    IDcard = StringField('card', validators=[DataRequired(), Length(min=18, max=20)]) 
    number = StringField('number', validators=[DataRequired(), Length(min=11, max=11)]) 
    department = StringField('department',
                        validators=[DataRequired(), Length(min=2, max=30)])  
    submit = SubmitField('确认')

    def validate_username(self, name):
        user = User.query.filter_by(name=name.data).first() 
        if user:
            raise ValidationError('That name is taken. Please choose a different one.')

class AdminLoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('登录')

class AdminRegistrationForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('注册')

class AddannouncementForm(FlaskForm):
    title = StringField('title', validators=[DataRequired(), Length(min=2, max=200)])
    body = StringField('body', validators=[DataRequired(), Length(min=2, max=200)])
    submit = SubmitField('发布')

class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('要求重设密码')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('重设密码')