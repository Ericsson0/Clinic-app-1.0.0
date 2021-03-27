import os
import secrets
from flask import render_template, url_for, flash, redirect, request, abort, session
from flaskblog import app, db, bcrypt, mail
from flaskblog.forms import PatientForm, MedicineForm, RegistrationForm, LoginForm, DetailForm, AddWorkLogForm, UpdateDoctorForm, AdminLoginForm, AdminRegistrationForm, AddannouncementForm, RequestResetForm, ResetPasswordForm
from flaskblog.models import User, Detail, Medicine, Patient, Worklog, Admin, Announcement
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message

# front-end-help == https://freefrontend.com/

@app.route('/')
def initialization():
    return render_template('initialization.html')  

@app.route('/release-note')
@login_required 
def release_note():
    return render_template('1.0.0 release-note.html')  

@app.route("/home") 
def home():
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
        patient = Patient(name=form.name.data, number=form.number.data, gender=form.gender.data, birth=form.birth.data,
        IDcard=form.IDcard.data, location=form.location.data) 
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
    form = PatientForm() 
    if form.validate_on_submit(): 
        patient.name = form.name.data 
        patient.number = form.number.data 
        patient.gender = form.gender.data 
        patient.birth = form.birth.data
        patient.IDcard = form.IDcard.data 
        db.session.commit()
        flash('患者信息已更改!', 'success') 
        return redirect(url_for('patient_info', name=patient.name))
    elif request.method == 'GET':
        form.name.data = patient.name  
        form.number.data = patient.number
        form.gender.data = patient.gender
        form.birth.data = patient.birth
        form.IDcard.data = patient.IDcard
    return render_template('add-patient.html', title='Update Patient',
                           form=form, legend='Update Patient') 

@app.route("/delete-patient/<int:patient_id>/", methods=['POST', 'GET'])  
@login_required 
def delete_patient(patient_id): 
    patient = Patient.query.get_or_404(patient_id) 
    detail = Detail.query.get_or_404(patient_id)
    db.session.delete(patient)
    db.session.delete(detail)  
    db.session.commit() 
    flash('患者已被删除!', 'success') 
    return redirect(url_for('patient'))

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
        detail = Detail(Symptom=form.Symptom.data, Check_result=form.Check_result.data, Preliminary_treatment_plan=form.Preliminary_treatment_plan.data, tag=form.tag.data, doctor=current_user) 
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

@app.route("/patient-detail-delete/<int:patient_id>", methods=['POST', 'GET']) 
@login_required 
def patient_detail_delete(patient_id): 
    detail = Detail.query.get_or_404(patient_id) 
    db.session.delete(detail) 
    db.session.commit() 
    flash('患者已被删除!', 'success')  
    return redirect(url_for('allpatient'))
 
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

@app.route("/addmedicine", methods=['GET', 'POST']) 
@login_required
def add_medicine():
    form = MedicineForm() 
    if form.validate_on_submit(): 
        medicine = Medicine(Vendor=form.Vendor.data, Quantity=form.Quantity.data, 
        Medicine_name=form.Medicine_name.data, Deadline=form.Deadline.data, Price=form.Price.data, How_to_use=form.How_to_use.data,
        doctor=current_user) 
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
 
@app.route("/delete-medicine/<int:medicine_id>", methods=['POST', 'GET']) 
@login_required 
def delete_medicine(medicine_id): 
    medicine = Medicine.query.get_or_404(medicine_id) 
    db.session.delete(medicine) 
    db.session.commit() 
    flash('药物已被删除!', 'success') 
    return redirect(url_for('allmedicine'))


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
        user.IDcard = form.IDcard.data 
        user.number = form.number.data
        user.department = form.department.data 
        db.session.commit()
        flash('医生信息已更改!', 'success')  
        return redirect(url_for('doctor_information', name=user.name))
    elif request.method == 'GET': 
        form.name.data = user.name
        form.IDcard.data = user.IDcard
        form.number.data = user.number
        form.department.data = user.department
    return render_template('update-doctor-info.html', title='Update Doctor', 
                           form=form, legend='Update Doctor') 

@app.route("/doctor-information/user/<string:name>", methods=['GET', 'POST'])  
@login_required  
def doctor_information(name):  
    user = User.query.filter_by(name=name).first_or_404()
    return render_template('doctor-info.html', user=user, values=Worklog.query.filter_by(author=user)) 

@app.route("/delete-doctor/<int:user_id>", methods=['POST', 'GET']) 
@login_required 
def delete_doctor(user_id): 
    user = User.query.get_or_404(user_id) 
    db.session.delete(user)  
    db.session.commit() 
    flash('医生已被删除!', 'success') 
    return redirect(url_for('alldoctor'))


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.name.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout") 
def logout():
    logout_user() 
    return redirect(url_for('login'))    
 

# admin

def send_admin_reset_email(admin):
    token = admin.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='clinicdonotreply@gmail.com',
                  recipients=[admin.email], )
    msg.body = f'''要重置密码，请访问以下链接：:
{url_for('admin_reset_token', token=token, _external=True)}
如果您没有发出此请求，则只需忽略此电子邮件，就不会进行任何更改。
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
    admin = Admin.verify_reset_token(token)
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


@app.route("/register-admin", methods=['GET', 'POST'])
def register_admin():  
    form = AdminRegistrationForm()  
    if form.validate_on_submit(): 
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        admin = Admin(email=form.email.data, password=hashed_password)
        db.session.add(admin) 
        db.session.commit() 
        flash('管理员帐号已被添加', 'success')
        return redirect(url_for('login_admin')) 
    return render_template('admin-register.html', title='Register', form=form)  

@app.route("/login-admin", methods=['GET', 'POST'])
def login_admin():
    form = AdminLoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(email=form.email.data).first()
        if admin and bcrypt.check_password_hash(admin.password, form.password.data):
            login_user(admin, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('a812faa788bbf630abc7097dd9474d1f3c6b8d49935d4da01064d3e27f37e8abce083240c59ad030ff844c6d2696ef60dcfd1ed14db0396938c0daa0692d4e81e7d9388b6cfcfbb8dd224268ea55aacbd2116f725949d22ff30e81a28b4567f6f43585deb4d2c81270996cc5292217d8cac7b02bab69a7f08d13da339c6cb0cd735fb0dfc54eb7b57b077b5733fc6179a6980ec3a15d68d15f7446c8c1f7573ec4d11ccbe5bcc7f6cf4f256edded95a57fe30420c3c92b4419bf0d73d5cc07c32558ccf3a1c9015b50e5ee72e3fb51dc83e5745e08b06566f565428881afe82d5f440bb6f4507dd8846ca69d9dabd9943d0bdef5a13d2da03db8c3826c54659ff387ed65a53b44a7f58b9f1551e178467024d8a6191cf7d4aec109329f4b21a42a8ffed06ef4f00fe292b84c601e6390513a7904ba1facd41da0d970c3612a7f984a71aaf37190096b592f98c3e7bb93ff14861b9fbcb2c247eed75d9acaa9555b1b3d9816758b8cdffe8e7bcda6b1883ac798f5bceb73c4fde8ab39ffeb3d1204f095b31140e4174989c2ebf251a90577ac179e739111b7fc378ad5987b1c8a6d5f4afbf8d3a937f59a81f1da2cfa4187e6da9d1642ea70e817dfc383dc006d84e808c4edbe0a193e75312635a3b08e50ceab16e8bdcd36c8506dc3c6e9fee0ffa1872c7e7f089c959f76ab7df9aac11fd6eacc99e9a59d1bd83e1a829c04e2e37c480df7642cf70735a589d1eae78b6239cd76ce4d6fc2c7e5cee60103589abbdb4af6be1a32b6b3ef9ffb68f565c86b281bbe2536499e4ca152b39788d889a6a8c2680c2f28ca9d96235f646fb2165d4ac44a3ff5c03c90ba48f4f48a4ea5bf93b08d4752074152a5130e0508f33d3b89ee0e6823bacf6843441926104a8f040c816c84b2a9ed8a07c1f8336980a5cdd25b30512e89b8b3540a6142e23aa965428200a14fd1d72cb1f3ffe23c7b8a53ea2db6363a111d1fc39abbd14672abe914641986c526ef78b67a33df73e6eddecacfe731bc357c5eb502ee84479db61495f7dc7fd4a40cc53baae4a147c2e7e367779f58b90780e67156534c19719e9dc7d567b726d83ea2df0bcfcad29ac5754b3ecac202f42b06e819c6642fb518972e394e5f785e51142c1bef838d53953376feefbfb73e683d3fddf1399983562ddf4c7ff5e892da2c8efb47e108783ec15f2ecfc8e35f96adf520d61736d8a62e7547f7a85ee3ba0417065d19135ff034b4ce30062e8820439d9c45c78f543593ea437fa45ed4ff2fe59cbbec65abbab45bcc512467067a86e3eba23f36ec09f03db411a200f2ded68fc95a8a78dfa933afac50e540a40850418057edf337a184efbc0d279df48223629bb1b4542b78222252681bbe1374ef692d93731443a54d3103ded42303c8205d3d9b196bdf3ddd13afea1afd45f5a9f68822d7901e51b485f66329c30609f622e111eaf815710c9bdaefb226736181d0dcbcb76ac5181f89e730742215c37ad716a54d0f1d85d058e432a6f2d7a8171bd00246e378dc8a9a6409ddeed95a7dbe07656dfa993f407b7a8779175e5a07d08b586d1224e7cbd2987e6dc1179a7282841be78de3ab4293f769965fe459fc3b1583fc08ddef12bb6147fbf09081d81bde8827291210d4f4e111fa2b37293d712539b28e0e7cdfb32766da7f08f2b6719eb091f5c3640ee3da30a45a5e8bcff2d0dfd27d48cdcbb9196a7dc0eb2578710ec401dd29d5f5a4_add_doctor_from_admin', admin_id=admin.id))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('admin-login.html', title='Login', form=form)


@app.route('/a812faa788bbf630abc7097dd9474d1f3c6b8d49935d4da01064d3e27f37e8abce083240c59ad030ff844c6d2696ef60dcfd1ed14db0396938c0daa0692d4e81e7d9388b6cfcfbb8dd224268ea55aacbd2116f725949d22ff30e81a28b4567f6f43585deb4d2c81270996cc5292217d8cac7b02bab69a7f08d13da339c6cb0cd735fb0dfc54eb7b57b077b5733fc6179a6980ec3a15d68d15f7446c8c1f7573ec4d11ccbe5bcc7f6cf4f256edded95a57fe30420c3c92b4419bf0d73d5cc07c32558ccf3a1c9015b50e5ee72e3fb51dc83e5745e08b06566f565428881afe82d5f440bb6f4507dd8846ca69d9dabd9943d0bdef5a13d2da03db8c3826c54659ff387ed65a53b44a7f58b9f1551e178467024d8a6191cf7d4aec109329f4b21a42a8ffed06ef4f00fe292b84c601e6390513a7904ba1facd41da0d970c3612a7f984a71aaf37190096b592f98c3e7bb93ff14861b9fbcb2c247eed75d9acaa9555b1b3d9816758b8cdffe8e7bcda6b1883ac798f5bceb73c4fde8ab39ffeb3d1204f095b31140e4174989c2ebf251a90577ac179e739111b7fc378ad5987b1c8a6d5f4afbf8d3a937f59a81f1da2cfa4187e6da9d1642ea70e817dfc383dc006d84e808c4edbe0a193e75312635a3b08e50ceab16e8bdcd36c8506dc3c6e9fee0ffa1872c7e7f089c959f76ab7df9aac11fd6eacc99e9a59d1bd83e1a829c04e2e37c480df7642cf70735a589d1eae78b6239cd76ce4d6fc2c7e5cee60103589abbdb4af6be1a32b6b3ef9ffb68f565c86b281bbe2536499e4ca152b39788d889a6a8c2680c2f28ca9d96235f646fb2165d4ac44a3ff5c03c90ba48f4f48a4ea5bf93b08d4752074152a5130e0508f33d3b89ee0e6823bacf6843441926104a8f040c816c84b2a9ed8a07c1f8336980a5cdd25b30512e89b8b3540a6142e23aa965428200a14fd1d72cb1f3ffe23c7b8a53ea2db6363a111d1fc39abbd14672abe914641986c526ef78b67a33df73e6eddecacfe731bc357c5eb502ee84479db61495f7dc7fd4a40cc53baae4a147c2e7e367779f58b90780e67156534c19719e9dc7d567b726d83ea2df0bcfcad29ac5754b3ecac202f42b06e819c6642fb518972e394e5f785e51142c1bef838d53953376feefbfb73e683d3fddf1399983562ddf4c7ff5e892da2c8efb47e108783ec15f2ecfc8e35f96adf520d61736d8a62e7547f7a85ee3ba0417065d19135ff034b4ce30062e8820439d9c45c78f543593ea437fa45ed4ff2fe59cbbec65abbab45bcc512467067a86e3eba23f36ec09f03db411a200f2ded68fc95a8a78dfa933afac50e540a40850418057edf337a184efbc0d279df48223629bb1b4542b78222252681bbe1374ef692d93731443a54d3103ded42303c8205d3d9b196bdf3ddd13afea1afd45f5a9f68822d7901e51b485f66329c30609f622e111eaf815710c9bdaefb226736181d0dcbcb76ac5181f89e730742215c37ad716a54d0f1d85d058e432a6f2d7a8171bd00246e378dc8a9a6409ddeed95a7dbe07656dfa993f407b7a8779175e5a07d08b586d1224e7cbd2987e6dc1179a7282841be78de3ab4293f769965fe459fc3b1583fc08ddef12bb6147fbf09081d81bde8827291210d4f4e111fa2b37293d712539b28e0e7cdfb32766da7f08f2b6719eb091f5c3640ee3da30a45a5e8bcff2d0dfd27d48cdcbb9196a7dc0eb2578710ec401dd29d5f5a4_add-doctor-from-admin/<int:admin_id>', methods=['GET', 'POST']) 
def a812faa788bbf630abc7097dd9474d1f3c6b8d49935d4da01064d3e27f37e8abce083240c59ad030ff844c6d2696ef60dcfd1ed14db0396938c0daa0692d4e81e7d9388b6cfcfbb8dd224268ea55aacbd2116f725949d22ff30e81a28b4567f6f43585deb4d2c81270996cc5292217d8cac7b02bab69a7f08d13da339c6cb0cd735fb0dfc54eb7b57b077b5733fc6179a6980ec3a15d68d15f7446c8c1f7573ec4d11ccbe5bcc7f6cf4f256edded95a57fe30420c3c92b4419bf0d73d5cc07c32558ccf3a1c9015b50e5ee72e3fb51dc83e5745e08b06566f565428881afe82d5f440bb6f4507dd8846ca69d9dabd9943d0bdef5a13d2da03db8c3826c54659ff387ed65a53b44a7f58b9f1551e178467024d8a6191cf7d4aec109329f4b21a42a8ffed06ef4f00fe292b84c601e6390513a7904ba1facd41da0d970c3612a7f984a71aaf37190096b592f98c3e7bb93ff14861b9fbcb2c247eed75d9acaa9555b1b3d9816758b8cdffe8e7bcda6b1883ac798f5bceb73c4fde8ab39ffeb3d1204f095b31140e4174989c2ebf251a90577ac179e739111b7fc378ad5987b1c8a6d5f4afbf8d3a937f59a81f1da2cfa4187e6da9d1642ea70e817dfc383dc006d84e808c4edbe0a193e75312635a3b08e50ceab16e8bdcd36c8506dc3c6e9fee0ffa1872c7e7f089c959f76ab7df9aac11fd6eacc99e9a59d1bd83e1a829c04e2e37c480df7642cf70735a589d1eae78b6239cd76ce4d6fc2c7e5cee60103589abbdb4af6be1a32b6b3ef9ffb68f565c86b281bbe2536499e4ca152b39788d889a6a8c2680c2f28ca9d96235f646fb2165d4ac44a3ff5c03c90ba48f4f48a4ea5bf93b08d4752074152a5130e0508f33d3b89ee0e6823bacf6843441926104a8f040c816c84b2a9ed8a07c1f8336980a5cdd25b30512e89b8b3540a6142e23aa965428200a14fd1d72cb1f3ffe23c7b8a53ea2db6363a111d1fc39abbd14672abe914641986c526ef78b67a33df73e6eddecacfe731bc357c5eb502ee84479db61495f7dc7fd4a40cc53baae4a147c2e7e367779f58b90780e67156534c19719e9dc7d567b726d83ea2df0bcfcad29ac5754b3ecac202f42b06e819c6642fb518972e394e5f785e51142c1bef838d53953376feefbfb73e683d3fddf1399983562ddf4c7ff5e892da2c8efb47e108783ec15f2ecfc8e35f96adf520d61736d8a62e7547f7a85ee3ba0417065d19135ff034b4ce30062e8820439d9c45c78f543593ea437fa45ed4ff2fe59cbbec65abbab45bcc512467067a86e3eba23f36ec09f03db411a200f2ded68fc95a8a78dfa933afac50e540a40850418057edf337a184efbc0d279df48223629bb1b4542b78222252681bbe1374ef692d93731443a54d3103ded42303c8205d3d9b196bdf3ddd13afea1afd45f5a9f68822d7901e51b485f66329c30609f622e111eaf815710c9bdaefb226736181d0dcbcb76ac5181f89e730742215c37ad716a54d0f1d85d058e432a6f2d7a8171bd00246e378dc8a9a6409ddeed95a7dbe07656dfa993f407b7a8779175e5a07d08b586d1224e7cbd2987e6dc1179a7282841be78de3ab4293f769965fe459fc3b1583fc08ddef12bb6147fbf09081d81bde8827291210d4f4e111fa2b37293d712539b28e0e7cdfb32766da7f08f2b6719eb091f5c3640ee3da30a45a5e8bcff2d0dfd27d48cdcbb9196a7dc0eb2578710ec401dd29d5f5a4_add_doctor_from_admin(admin_id): 
    admin = Admin.query.get_or_404(admin_id)
    form = RegistrationForm() 
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(name=form.name.data, IDcard=form.IDcard.data, number=form.number.data, gender=form.gender.data, email=form.email.data, department=form.department.data, password=hashed_password)
        db.session.add(user)  
        db.session.commit()   
        flash('已添加此医生', 'success')
        return redirect(url_for('login')) 
    return render_template('register.html', admin=admin, title='Register', form=form)


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
    form = AddWorkLogForm() 
    if form.validate_on_submit():  
        worklog = Worklog(title=form.title.data, body=form.body.data, tag=form.tag.data, author=current_user) 
        db.session.add(worklog) 
        db.session.commit() 
        flash('工作日志已被加入进数据库当中', 'success')  
        return redirect(url_for('worklog'))    
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
    if current_user.id != 1:
        return render_template('forbidden.html')
    else:
        form = AddannouncementForm() 
        if form.validate_on_submit():  
            announcement = Announcement(title=form.title.data, body=form.body.data, author=current_user) 
            db.session.add(announcement)  
            db.session.commit() 
            flash('工作日志已被加入进数据库当中', 'success')  
            return redirect(url_for('home'))     
        return render_template('add-announcement.html', title='Add Announcement', form=form) 

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
