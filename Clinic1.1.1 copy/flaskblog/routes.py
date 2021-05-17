import os
import jwt 
import secrets
from flask import render_template, url_for, flash, redirect, request, abort, session, jsonify, make_response
from flaskblog import app, db, bcrypt, mail
from flaskblog.forms import PatientForm, MedicineForm, RegistrationForm, LoginForm, DetailForm, AddWorkLogForm, UpdateDoctorForm, AdminLoginForm, AdminRegistrationForm, AddannouncementForm, RequestResetForm, ResetPasswordForm, ChangePatientForm
from flaskblog.models import User, Detail, Medicine, Patient, Worklog, Admin1, Announcement
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from datetime import datetime, timedelta
from werkzeug.useragents import UserAgent
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
from functools import wraps

# front-end-help == https://freefrontend.com/

'''
user = db.session.query(User.name).first()
    for i in User.query.all():
        ip = request.remote_addr
        #user_agent = UserAgent(request.headers.get('User-Agent'))
        #print(user_agent.platform)
        print(ip) 
        if ip in i.host:
            return redirect(url_for('doctor_information', name=user.name))
        elif ip not in i.host: 
'''

@app.route('/', methods=['GET']) 
def initialization():
    for i in Admin1.query.all():
        ip = request.remote_addr
        user_agent = UserAgent(request.headers.get('User-Agent'))
        print(user_agent.platform)
        print(ip) 
        user = db.session.query(User.name).first() 
        if ip in i.host:
            return redirect(url_for('doctor_information', name=user.name))
        elif ip not in i.host: 
            return render_template('initialization.html')  

    
@app.route('/release-note')
@login_required 
def release_note():
    return render_template('release-note.html')  

@app.route("/lol") 
def lol():
    announcements = Announcement.query.order_by(Announcement.date_posted.desc())
    return render_template("home.html", announcements=announcements)  

@app.route('/404/more')
def more_404():
    return render_template('more-404.html')

@app.route('/explain')
def explain():
    return render_template('explain.html')

# add patient section
@app.route("/patient") 
@login_required 
def patient(): 
    page = request.args.get('page', 1, type=int) # get all the posts from db file
    patients = Patient.query.order_by(Patient.create.desc()).paginate(page=page, per_page=10) # posts were order by date, 20 posts each page
    return render_template('patient.html', patients=patients)

@app.route('/allpatient')
@login_required  
def allpatient():
    return render_template('find-patient.html', values=Patient.query.all())   

@app.route('/patient-info-for/<string:name>')
@login_required  
def patient_info_for(name):
    patient = Patient.query.filter_by(name=name).first_or_404()
    return render_template('find-patient-history.html', patient=patient, values=Patient.query.filter_by(name=name))   

@app.route("/addpatient", methods=['GET', 'POST']) 
@login_required 
def addpatient(): 
    form = PatientForm() 
    if form.validate_on_submit():
        patient = Patient(name=form.name.data, number=form.number.data, gender=form.gender.data, ID_Card=form.ID_Card.data, year=form.year.data, month=form.month.data,
        day=form.day.data, street=form.street.data)   
        db.session.add(patient) 
        db.session.commit()
        flash('此患者已被加入进数据库当中', 'success') 
        return redirect(url_for('patient')) 
    return render_template('add-patient.html', title='Add Patient', form=form) 

@app.route("/patient/<int:patient_id>") 
@login_required
def patient_id(patient_id): 
    patient = Patient.query.get_or_404(patient_id)
    return render_template('patient_info.html', patient=patient)  
 
@app.route("/update-patient/<int:patient_id>", methods=['GET', 'POST']) 
@login_required 
def update_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)  
    form = ChangePatientForm() 
    if form.validate_on_submit(): 
        patient.number = form.number.data 
        patient.street = form.street.data
        db.session.commit()
        flash('患者信息已更改!', 'success') 
        return redirect(url_for('patient_info', name=patient.name))
    elif request.method == 'GET':
        form.number.data = patient.number
        form.street.data = patient.street
    return render_template('change-patient.html', title='Update Patient',
                           form=form, legend='Update Patient') 

@app.route("/patient-info/<string:name>") 
@login_required
def patient_info(name): 
    patient = Patient.query.filter_by(name=name).first_or_404()
    return render_template('patient_info.html', patient=patient)    

@app.errorhandler(404)
def not_found(e):
  return render_template('custom_page.html'), 404

@app.route("/patientdetail/<int:patient_id>") 
@login_required 
def patientdetail(patient_id): 
    detail = Detail.query.get_or_404(patient_id)
    patient = Patient.query.get_or_404(patient_id)
    return render_template('patient_detail.html', detail=detail, patient=patient)
 
@app.route("/add-patient-detail/<int:patient_id>", methods=['GET', 'POST']) 
@login_required  
def add_patient_detail(patient_id): 
    form = DetailForm()   
    if form.validate_on_submit():  
        detail = Detail(Symptom=form.Symptom.data, Check_result=form.Check_result.data, 
        Preliminary_treatment_plan=form.Preliminary_treatment_plan.data, tag=form.tag.data, user=current_user) 
        db.session.add(detail) 
        db.session.commit() 
        flash('此患者已被加入进数据库当中', 'success') 
        return redirect(url_for('patient'))     
    return render_template('add-patient-detail.html', title='Add Patient Detail', form=form)   

@app.route("/patient-detail-update/<int:patient_id>", methods=['GET', 'POST'])  
@login_required   
def patient_detail_update(patient_id): 
    detail = Detail.query.get_or_404(patient_id)   
    form = DetailForm()  
    if form.validate_on_submit(): 
        detail.Symptom = form.Symptom.data 
        detail.Check_result = form.Check_result.data 
        detail.Preliminary_treatment_plan = form.Preliminary_treatment_plan.data 
        detail.tag = form.tag.data
        db.session.commit()
        flash('患者信息已更改!', 'success') 
        return redirect(url_for('patientdetail', patient_id=detail.id))
    elif request.method == 'GET':
        form.Symptom.data = detail.Symptom
        form.Check_result.data = detail.Check_result
        form.Preliminary_treatment_plan.data = detail.Preliminary_treatment_plan 
        form.tag.data = detail.tag
    return render_template('add-patient-detail.html', title='Update Patient-Detail',
                           form=form, legend='Update Patient-Detail', patient=patient) 
 
# add medicine section 
@app.route("/medicine") 
@login_required
def medicine_info():
    page = request.args.get('page', 1, type=int) # get all the posts from db file
    medicines = Medicine.query.order_by(Medicine.time_get.desc()).paginate(page=page, per_page=10)
    return render_template('medicine.html', medicines=medicines) 

@app.route('/allmedicine')
@login_required 
def allmedicine():
    return render_template('find-medicine.html', values=Medicine.query.all())  

@app.route('/medicine-info-for/<string:Medicine_name>')
@login_required  
def medicine_info_for(Medicine_name):
    medicine = Medicine.query.filter_by(Medicine_name=Medicine_name).first_or_404()
    return render_template('find-medicine-history.html', medicine=medicine, values=Medicine.query.filter_by(Medicine_name=Medicine_name)) 

@app.route("/medicine/<string:Medicine_name>") 
@login_required
def medicine(Medicine_name):  
    medicine = Medicine.query.filter_by(Medicine_name=Medicine_name).first_or_404() 
    return render_template('medicine_info.html', medicine=medicine) 

@app.route("/addmedicine", methods=['POST']) 
@login_required
def add_medicine():
    form = MedicineForm() 
    if form.validate_on_submit(): 
        date = request.form['date']
        medicine = Medicine(Vendor=form.Vendor.data, Quantity=form.Quantity.data, 
        Medicine_name=form.Medicine_name.data, date=date, Price=form.Price.data, How_to_use=form.How_to_use.data,
        user=current_user) 
        db.session.add(medicine)
        db.session.commit() 
        flash('此药物已被加入进数据库当中', 'success') 
        return redirect(url_for('medicine', Medicine_name=medicine.Medicine_name)) 
    return render_template('add-medicine.html', title='Add Medicine', form=form)  

@app.route("/update-medicine/<int:medicine_id>", methods=['GET', 'POST']) 
@login_required 
def update_medicine(medicine_id): 
    medicine = Medicine.query.get_or_404(medicine_id)  
    form = MedicineForm() 
    if form.validate_on_submit(): 
        medicine.Vendor = form.Vendor.data 
        medicine.Quantity = form.Quantity.data 
        medicine.Medicine_name = form.Medicine_name.data 
        medicine.Deadline = form.Deadline.data 
        medicine.Price = form.Price.data 
        medicine.How_to_use = form.How_to_use.data
        db.session.commit()
        flash('药物信息已更改!', 'success')  
        return redirect(url_for('medicine', Medicine_name=medicine.Medicine_name))
    elif request.method == 'GET': 
        form.Vendor.data = medicine.Vendor 
        form.Quantity.data = medicine.Quantity
        form.Medicine_name.data = medicine.Medicine_name
        form.Deadline.data =medicine.Deadline    
        form.Price.data = medicine.Price 
        form.How_to_use.data = medicine.How_to_use
    return render_template('add-medicine.html', title='Update Medicine',
                           form=form, legend='Update Medicine') 

# all doctor section

@app.route('/doctor')
@login_required
def doctor():
    page = request.args.get('page', 1, type=int) # get all the posts from db file
    users = User.query.order_by(User.create.desc()).paginate(page=page, per_page=10) 
    return render_template('doctor.html', users=users)

@app.route('/alldoctor')
@login_required
def alldoctor():
    return render_template('find-doctor.html', values=User.query.all())  

@app.route("/update-doctor/<int:user_id>", methods=['GET', 'POST']) 
@login_required 
def update_doctor(user_id):
    user = User.query.get_or_404(user_id)  
    form = UpdateDoctorForm()  
    if form.validate_on_submit(): 
        user.name = form.name.data 
        user.number = form.number.data
        user.department = form.department.data 
        db.session.commit()
        flash('医生信息已更改!', 'success')  
        return redirect(url_for('doctor_information', name=user.name))
    elif request.method == 'GET': 
        form.name.data = user.name
        form.number.data = user.number
        form.department.data = user.department
    return render_template('update-doctor-info.html', title='Update Doctor', 
                           form=form, legend='Update Doctor') 

@app.route("/home-for/<string:name>", methods=['POST', 'GET'])
@login_required 
def doctor_information(name):   
    user = User.query.filter_by(name=name).first_or_404()
    # Total new patient
    amount = Patient.query.all() # total new patient
    amount_patient = len(amount)
    # Total patient
    mylist = db.session.query(Patient.name).all() 
    mylist1 = len(list(dict.fromkeys(mylist))) # remove duplicate and use len() to count the total patient
    # Total patient for 4 weeks
    current_time = datetime.now() 
    time = timedelta(weeks = 4) 
    four_weeks_ago = current_time - time 
    filter_by_month = db.session.query(Patient.name).filter(Patient.create > four_weeks_ago).all() # filter by the patient during this 4 weeks
    filter_by_month_1 = len(list(dict.fromkeys(filter_by_month))) 
    # Total patient for today
    time_1 = timedelta(days = 1) # filter last 4 weeks
    today = current_time - time_1 # start the counter 
    filter_by_today = db.session.query(Patient.name).filter(Patient.create > today).all() # filter by the patient during this 4 weeks
    filter_by_today_1 = len(list(dict.fromkeys(filter_by_today))) 
    return render_template('file.html', user=user, mylist1=mylist1, amount_patient=amount_patient, 
    values=Worklog.query.filter_by(author=user), 
    filter_by_month_1=filter_by_month_1, filter_by_today_1=filter_by_today_1)    

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        user = db.session.query(User.name).first()
        return redirect(url_for('doctor_information', name=user.name))
    form = LoginForm() 
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.name.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('doctor_information', name=user.name))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout") 
def logout(): 
    logout_user() 
    return redirect(url_for('login'))    
 

# admin


#def send_admin_reset_email(admin):
 #   token = admin.get_reset_token()
  #  msg = Message('Password Reset Request',
   #               sender='clinicdonotreply@gmail.com',
    #              recipients=[admin.email], )
    #msg.body = f'''要重置密码，请访问以下链接：:
#{url_for('admin_reset_token', token=token, _external=True)}
#如果您没有发出此请求，则只需忽略此电子邮件，就不会进行任何更改。
'''
    mail.send(msg)


@app.route("/admin_reset_password", methods=['GET', 'POST'])
def admin_reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(email=form.email.data).first()
        send_admin_reset_email(admin)
        flash('已发送一封电子邮件，其中包含有关重置密码的说明。', 'info')
        return redirect(url_for('login_admin'))
    return render_template('admin_reset_request.html', title='Reset Password', form=form)


@app.route("/admin_reset_password/<token>", methods=['GET', 'POST'])
def admin_reset_token(token):
    admin = Admin1.verify_reset_token(token)
    if Admin is None:
        flash('那是无效或过期的令牌', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        admin.password = hashed_password
        db.session.commit()
        flash('您的密码已更新！ 您现在可以登录', 'success')
        return redirect(url_for('login_admin'))
    return render_template('admin_reset_token.html', title='Reset Password', form=form)

for i in db.session.query(Admin.id).all():
        if 1 in i:
          return redirect(url_for('login_admin')) 
        elif 1 not in i:
'''
@app.route("/register-admin", methods=['GET', 'POST'])
def register_admin():   
    form = AdminRegistrationForm()  
    if form.validate_on_submit(): 
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        admin = Admin1(email=form.email.data, password=hashed_password, host=request.remote_addr)
        db.session.add(admin) 
        db.session.commit() 
        flash('管理员帐号已被添加', 'success')
        return redirect(url_for('login_admin')) 
    return render_template('admin-register.html', title='Register', form=form)   

@app.route("/login-admin")
@login_required 
def login_admin():
    auth = request.authorization

    if auth and auth.password == 'secret':
        token = jwt.encode({'user' : auth.username}, app.config['SECRET_KEY'])
        toknen = jsonify({'token' : token.decode('UTF-8')})
        return redirect(url_for('add_doctor', token=token))

    return make_response('无法通过!', 401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token') 

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message' : 'Token is invalid!'}), 403

        return f(*args, **kwargs)

    return decorated

@app.route('/protected', methods=['POST', 'GET'])
@token_required
def protected():
    return render_template('admin_page.html')

@app.route('/add-doctor', methods=['GET', 'POST']) 
@token_required 
def add_doctor():
    form = RegistrationForm() 
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(name=form.name.data, number=form.number.data, gender=form.gender.data, email=form.email.data, department=form.department.data, password=hashed_password)
        db.session.add(user)  
        db.session.commit()   
        flash('已添加此医生', 'success')
        return redirect(url_for('doctor_information', name=user.name)) 
    return render_template('register.html', admin=admin, title='Register', form=form)

class MyView(BaseView):
    @expose('/')
    def index(self):
        return self.render('admin_page.html')

admin = Admin(app, name="管理员")
admin.add_view(ModelView(Patient, db.session, name="患者"))
admin.add_view(ModelView(Medicine, db.session, name="药物"))    
admin.add_view(ModelView(User, db.session, name="大夫")) 
admin.add_view(ModelView(Worklog, db.session, name="工作日志"))

# doctor work log 

@app.route('/worklog')
@login_required  
def worklog():  
    page = request.args.get('page', 1, type=int) 
    worklogs = Worklog.query.order_by(Worklog.date_posted.desc()).paginate(page=page, per_page=10)
    return render_template('worklog.html', worklogs=worklogs)
  
@app.route('/add-work-log/<string:name>', methods=['GET', 'POST'])
@login_required  
def add_work_log(name): 
    user = db.session.query(Patient.name).first_or_404()
    form = AddWorkLogForm() 
    if form.validate_on_submit():  
        worklog = Worklog(title=form.title.data, body=form.body.data, tag=form.tag.data, author=current_user) 
        db.session.add(worklog) 
        db.session.commit() 
        flash('工作日志已被加入进数据库当中', 'success')  
        return redirect(url_for('doctor_information', name=user.name))    
    return render_template('add-work-log.html', title='Add Worklog', form=form) 

@app.route('/find-all-work-log', methods=['GET']) 
@login_required 
def find_all_work_log():
    if current_user.id != 1:
        return render_template('forbidden.html') 
    else:
        return render_template('find-work-log.html', values=Worklog.query.all()) 

@app.route('/work-log-info/<string:name>', methods=['GET', 'POST'])  
@login_required    
def the_work_log_for(name):      
    user = User.query.filter_by(name=name).first_or_404()
    return render_template('find-work-log.html', values=Worklog.query.filter_by(author=user))  

@app.route('/work/log-for/the/doctor/id/<int:worklog_id>') 
@login_required 
def work_log_for_the_doctor_id(worklog_id):  
    worklog = Worklog.query.get_or_404(worklog_id)
    return render_template('worklog-info.html', worklog=worklog)      

@app.route('/add-announcement', methods=['GET', 'POST'])
@login_required  
def add_announcement(): 
    user = db.session.query(User.name).first_or_404()
    if current_user.id != 1:
        return render_template('forbidden.html')
    else:
        form = AddannouncementForm() 
        if form.validate_on_submit():  
            announcement = Announcement(title=form.title.data, body=form.body.data, author=current_user) 
            db.session.add(announcement)  
            db.session.commit() 
            flash('工作日志已被加入进数据库当中', 'success')  
            return redirect(url_for('doctor_information', name=user.name))     
        return render_template('add-announcement.html', title='Add Announcement', user=user, form=form) 

@app.route('/announcement/<int:announcement_id>') 
@login_required 
def announcement(announcement_id):  
    announcement = Announcement.query.get_or_404(announcement_id)
    return render_template('announcement-info.html', announcement=announcement) 

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='clinicdonotreply@gmail.com',
                  recipients=[user.email], )
    msg.body = f'''要重置密码，请访问以下链接：:
{url_for('reset_token', token=token, _external=True)}
如果您没有发出此请求，则只需忽略此电子邮件，就不会进行任何更改。
'''
    mail.send(msg) 


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('已发送一封电子邮件，其中包含有关重置密码的说明。', 'info')
        return redirect(url_for('logout'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('您的密码已更新！ 您现在可以登录', 'success')
        return redirect(url_for('logout'))
    return render_template('reset_token.html', title='Reset Password', form=form)
