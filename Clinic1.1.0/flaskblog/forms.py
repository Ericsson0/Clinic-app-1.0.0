from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flaskblog.models import User

class DetailForm(FlaskForm):
    Symptom = StringField('Symptom') 
    Check_result = StringField('Check_result')
    Preliminary_treatment_plan = StringField('Preliminary_treatment_plan')
    tag = StringField('tag') 
    submit = SubmitField('添加') 

class MedicineForm(FlaskForm):
    Vendor = StringField('Vendor') 
    Quantity = StringField('Quantity') 
    Medicine_name = StringField('Medicine') 
    Deadline = StringField('Deadline') 
    Price = StringField('Price')
    How_to_use = StringField('How_to_use')
    submit = SubmitField('添加') 

class RegistrationForm(FlaskForm):
    name = StringField('Name',
                           validators=[DataRequired(), Length(min=2, max=20)])
    number = StringField('number') 
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
    number = StringField('number') 
    gender = SelectField('gender', choices=[('女', '女'), ('男', '男')]) 
    year = StringField('year') 
    month = SelectField('month', choices=[('01', '01'), ('02', '02'), ('03', '03'), ('04', '04'),
                                ('05', '05'), ('06', '06'), ('07', '07'), ('08', '08'), ('09', '09'), 
                                ('10', '10'), ('11', '11'), ('12', '12')]) 
    day = SelectField('day', choices=[('01', '01'), ('02', '02'), ('03', '03'), ('04', '04'),
                                ('05', '05'), ('06', '06'), ('07', '07'), ('08', '08'), ('09', '09'), 
                                ('10', '10'), ('11', '11'), ('12', '12'), ('13', '13'), ('14', '14'), 
                                ('15', '15'), ('16', '16'), ('17', '17'), ('18', '18'), ('19', '19'), 
                                ('20', '20'), ('21', '21'), ('22', '22'), ('23', '23'), ('24', '24'),
                                ('25', '25'), ('26', '26'), ('27', '27'), ('28', '28'), ('29', '29'),
                                ('30', '30'), ('31', '31') ])  
    street = StringField('street')  
    submit = SubmitField('添加')  

class AddWorkLogForm(FlaskForm):
    title = StringField('title') 
    body = StringField('body') 
    tag = StringField('tag') 
    submit = SubmitField('添加')

class UpdateDoctorForm(FlaskForm):
    name = StringField('Name',
                           validators=[DataRequired(), Length(min=2, max=20)])
    number = StringField('number') 
    department = StringField('department')  
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
    title = StringField('title')
    body = StringField('body')
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