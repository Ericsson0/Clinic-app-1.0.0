from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flaskblog import db, login_manager, app
from flask_login import UserMixin

@login_manager.user_loader 
def load_user(user_id): 
    return User.query.get(int(user_id))


class Patient(db.Model, UserMixin): 
    __bind_key__ = 'patient'
    id = db.Column(db.Integer, primary_key=True) 
    name = db.Column(db.String(10), nullable=False)
    number = db.Column(db.String(11), unique=False, nullable=False) 
    gender = db.Column(db.String(2), nullable=False) 
    birth = db.Column(db.String(10), nullable=False) 
    IDcard = db.Column(db.String(12), nullable=False) # 身份证 
    location = db.Column(db.String(50), nullable=False) 
    create = db.Column(db.DateTime, nullable=False, default=datetime.now)    

class Detail(db.Model, UserMixin): 
    __bind_key__ = 'detail'
    id = db.Column(db.Integer, primary_key=True) 
    Symptom = db.Column(db.String(500), nullable=False)  
    Check_result = db.Column(db.String(500), nullable=False) 
    Preliminary_treatment_plan = db.Column(db.String(500), nullable=False)
    tag = db.Column(db.String(100), nullable=False) 
    #tag slectfield
    Date_of_diagnosis = db.Column(db.DateTime, nullable=False, default=datetime.now)   
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 

class Medicine(db.Model): 
    __bind_key__ = 'medicine'
    id = db.Column(db.Integer, primary_key=True) 
    Vendor = db.Column(db.String(200), nullable=False)
    Quantity = db.Column(db.String(5), nullable=False) 
    Medicine_name = db.Column(db.String(200), nullable=False) 
    Deadline = db.Column(db.String(20), nullable=False) 
    Price = db.Column(db.String(10), nullable=False) 
    How_to_use = db.Column(db.String(200), nullable=False) 
    time_get = db.Column(db.DateTime, nullable=False, default=datetime.now) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    IDcard = db.Column(db.String(12), nullable=False)
    number = db.Column(db.String(11), unique=False, nullable=False) 
    gender = db.Column(db.String(2), nullable=False) 
    email = db.Column(db.String(120), unique=True, nullable=False)
    department = db.Column(db.String(30), unique=False, nullable=False)
    create = db.Column(db.DateTime, nullable=False, default=datetime.now) 
    password = db.Column(db.String(60), nullable=False) 
    worklogs = db.relationship('Worklog', backref='author', lazy=True) 
    details = db.relationship('Detail', backref='doctor', lazy=True)  
    announcements = db.relationship('Announcement', backref='author', lazy=True)  
    medicines = db.relationship('Medicine', backref='doctor', lazy=True)  

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

class Admin(db.Model, UserMixin):
    __bind_key__ = 'admin'
    id = db.Column(db.Integer, unique=True, primary_key=True)
    email = db.Column(db.String(20), unique=True, nullable=False)
    create = db.Column(db.DateTime, unique=True, nullable=False, default=datetime.now) 
    password = db.Column(db.String(60), nullable=False, default='admin') 

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'admin_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            admin_id = s.loads(token)['admin_id']
        except:
            return None
        return Admin.query.get(admin_id)

class Worklog(db.Model):  
    __bind_key__ = 'work_log'
    id = db.Column(db.Integer, primary_key=True) 
    title = db.Column(db.String(200), unique=False, nullable=False)
    body = db.Column(db.String(200), unique=False, nullable=False)
    tag = db.Column(db.String(200), unique=False, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
         
class Announcement(db.Model):
    __bind_key__ = 'announcement'
    id = db.Column(db.Integer, primary_key=True) 
    title = db.Column(db.String(200), unique=False, nullable=False)
    body = db.Column(db.String(200), unique=False, nullable=False) 
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  