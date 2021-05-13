from flask import Flask, render_template, request, flash, redirect, url_for, abort, session, jsonify
from functools import wraps
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from datetime import datetime, timedelta, date
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, TimedJSONWebSignatureSerializer
from flask_wtf import FlaskForm, RecaptchaField, Recaptcha
from wtforms import StringField, PasswordField, validators, ValidationError, SubmitField, HiddenField, SelectField
from wtforms.validators import DataRequired, InputRequired
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
import uuid
import pymongo

#.........................................................................................

app = Flask(__name__)
app.config["SECRET_KEY"] = "thisisasecret"
app.permanent_session_lifetime = timedelta(hours=1)
app.config['RECAPTCHA_PUBLIC_KEY'] = "6Le1_8UaAAAAABXYdsaQw1j9U9V9aZ-hdPDp1Env"
app.config['RECAPTCHA_PRIVATE_KEY'] = "6Le1_8UaAAAAAP14zlv5y3mnsYQxTfncwst1m5Z9"

#Mail Config..................................................................................................................................................................................

emailSeacret = URLSafeTimedSerializer("IamSeacret")
resetSeacret = TimedJSONWebSignatureSerializer("IamResetSeacret", expires_in = 3600)
app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = "kunursinghome@gmail.com"
app.config["MAIL_PASSWORD"] = "KU123456!"
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
mail = Mail(app)

#csrf ..................................................................................................................................................................................

csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

#Connect MongoDB..................................................................................................................................................................................
app.config['MONGO_URI'] =  "mongodb+srv://root:Group1147@cluster0.q8ief.mongodb.net/NMS?retryWrites=true&w=majority" #
mongo = PyMongo(app)
mydb = mongo.db["NMS"]
userDB = mydb["userTable"]
bookingDB =  mydb["bookingTable"]
billDB = mydb["billTable"]
activityDB = mydb["activityTable"]
activityAppliedDB = mydb["activityAppliedTable"]

#Form setting..................................................................................................................................................................................

#Form For Index
class IndexForm(FlaskForm):
    pass

#Form For Login
class uniForm(FlaskForm):
    pass

#Form For Login
class LoginForm(FlaskForm):
    email = StringField("Email", [InputRequired()])
    password = PasswordField("Password", [InputRequired()])
    loginBtn = SubmitField("Login")
    loginRecap = RecaptchaField(validators = [Recaptcha(message = "Please Click the Human Button")])

#Form For Register
class RegisterForm(FlaskForm):
    email = StringField("Email", [InputRequired(), validators.Regexp("^[a-zA-Z0-9]+@[a-zA-Z]+\.(com|net|edu|org){1,39}$", message = "Please input a valid email")])
    username = StringField("Name", [validators.Regexp("^(?!.*[!@#$%^&*])[A-Za-z\d]{7,15}$", message = "Please input a valid Username and at least 8 characters")])
    password = PasswordField("Password", [validators.Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{11,15}$", message = "Must at least a number, a letter and a special characters and at least 12 characters")])
    secpassword = PasswordField("Confirm Password", [validators.EqualTo("password", message = "Password not match")])
    registerBtn = SubmitField("Register")
    
    #Check If User Exist
    def validate_email(FlaskForm, email):
        if userDB.find_one({"email" : email.data}) or userDB.find_one({"_id" : uuid.uuid4().hex}):
            raise ValidationError("User Exist")

#Form For Sending Reset Password Email
class RequestResetPassword(FlaskForm):
    email = StringField("Email", [InputRequired(), validators.Regexp("^[a-zA-Z0-9]+@[a-zA-Z]+\.(com|net|edu|org){1,39}$", message = "Please input a valid email")])
    requestResetPasswordBtn = SubmitField("Submit")


#Form For Reset Password
class ResetPasswordForm(FlaskForm):
    token = HiddenField("token")
    password = PasswordField("Password", [InputRequired(), validators.Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{11,15}$", message = "Must at least a number, a letter and a special characters and at least 12 characters")])
    secpassword = PasswordField("Confirm Password", [validators.EqualTo("password", message = "Password not match")])
    resetPasswordBtn = SubmitField("Submit")

#Reset Password Page
@app.route("/ResetPassword/<resetToken>", methods = ["GET", "POST"])
def resetPasswordPage(resetToken):
    if session.get("logged in") == True:
        return redirect(url_for("loginPage"))

    form = ResetPasswordForm()

    try:
        if request.method == "POST" and form.validate_on_submit():
            password = form.password.data
            secpassword = form.secpassword.data   

            modifyDate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            
            email = resetSeacret.loads(resetToken)
            userDB.update_one({"email" : email}, {"$set" : {"password" : bcrypt.generate_password_hash(password).decode("utf-8")}})
            userDB.update_one({"email" : email}, {"$set" : {"last_modified_time" : modifyDate}})

            flash("Password Changed")
            return redirect(url_for("loginPage"))
        return render_template("ResetPassword.html", form = form, resetToken = resetToken)
    except SignatureExpired:
        flash("Token Expired")
        return redirect(url_for("loginPage"))
    except:
        abort(500)



#Form For adminRegister
class adminRegisterForm(FlaskForm):
    email = StringField("Email", [InputRequired(), validators.Regexp("^[a-zA-Z0-9]+@[a-zA-Z]+\.(com|net|edu|org){1,39}$", message = "Please input a valid email")])
    username = StringField("Name", [InputRequired(), validators.Regexp("^(?!.*[!@#$%^&*])[A-Za-z\d]{7,15}$", message = "Please input a valid Username and at least 8 characters")])
    room_no = StringField("Room No.", [InputRequired(), validators.Regexp("^([0-9]{1,4})$", message = "Please input a correct Room no.")])
    password = PasswordField("Password", [InputRequired(), validators.Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{11,15}$", message = "Must at least a number, a letter and a special characters and at least 12 characters")])
    otherInfo = StringField("Other Information")
    del_email = StringField("Email", [InputRequired()])
    registerBtn = SubmitField("Create")
    updateBtn = SubmitField("Update")
    delBtn = SubmitField("Delete")

    #Check If User Exist
    def validate_email(FlaskForm, email):
        if userDB.find_one({"email" : email.data}) or userDB.find_one({"_id" : uuid.uuid4().hex}):
            raise ValidationError("User Exist")

#Form For Create Activity
class activityForm(FlaskForm):
    activityNo = StringField("Activity No.", [InputRequired()])
    name = StringField("Activity Name", [InputRequired()])
    place = StringField("Activity Place", [InputRequired()])
    detail = StringField("Activity Detail")
    del_activityNo = StringField("Activity No.", [InputRequired()])
    check_activityNo = StringField("Activity No.", [InputRequired()])
    createBtn = SubmitField("Create")
    updateBtn = SubmitField("Update")
    delBtn = SubmitField("Delete")
    checkBtn = SubmitField("Check")

#Form For Bill
class billForm(FlaskForm):
    email = StringField("Email", [InputRequired(), validators.Regexp("^[a-zA-Z0-9]+@[a-zA-Z]+\.(com|net|edu|org){1,39}$", message = "Please input a valid email")])
    price = StringField("Amount", [InputRequired()])
    up_email = StringField("Email", [InputRequired(), validators.Regexp("^[a-zA-Z0-9]+@[a-zA-Z]+\.(com|net|edu|org){1,39}$", message = "Please input a valid email")])
    up_price = StringField("Amount", [InputRequired()])
    del_email = StringField("Email", [InputRequired(), validators.Regexp("^[a-zA-Z0-9]+@[a-zA-Z]+\.(com|net|edu|org){1,39}$", message = "Please input a valid email")])
    check_email = StringField("Email", [InputRequired(), validators.Regexp("^[a-zA-Z0-9]+@[a-zA-Z]+\.(com|net|edu|org){1,39}$", message = "Please input a valid email")])
    submitBtn = SubmitField("Submit")
    updateBtn = SubmitField("Update")
    delBtn = SubmitField("Delete")
    checkBtn = SubmitField("Check")

#Form for Elderly submit Activity Application
class elderlyActivity(FlaskForm):
    activityNo = StringField("Activity No.", [InputRequired()])
    joinBtn = SubmitField("Join")
    rejectBtn = SubmitField("Reject")

#Form For Activate
class ActivateForm(FlaskForm):
    pass

#Manager page.................................................................................................................................................................................
#Manager Page
@app.route("/Manager", methods = ["GET", "POST"])
def managerPage():
    if session.get("role") != "Manager":
        return redirect(url_for("loginPage"))

    users = userDB.find({ "role" : { "$in" : ["Manager", "Admin", "Guest"]}})
    return render_template('Manager.html', users = users)

#Form For Adding User
class AddUserForm(FlaskForm):
    email = StringField("Email", [InputRequired(), validators.Regexp("^[a-zA-Z0-9]+@[a-zA-Z]+\.(com|net|edu|org){1,39}$", message = "Please input a valid email")])
    username = StringField("Username", [validators.Regexp("^(?!.*[!@#$%^&*])[A-Za-z\d]{7,15}$", message = "Please input a valid Username and at least 8 characters")])
    password = PasswordField("Password", [validators.Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{11,15}$", message = "Must at least a number, a letter and a special characters and at least 12 characters")])
    role = SelectField("Role", choices = [("Manager", "Manager"), ("Admin", "Admin"), ("Guest", "Guest")])
    addUserBtn = SubmitField("Submit")
    
    
    #Check If User Exist
    def validate_email(FlaskForm, email):
        if userDB.find_one({"email" : email.data}) or userDB.find_one({"_id" : uuid.uuid4().hex}):
            raise ValidationError("User Exist")

#Add User Page
@app.route("/Manager/AddUser", methods = ["GET", "POST"])
def addUserPage():
    if session.get("role") != "Manager":
        return redirect(url_for("loginPage"))

    form = AddUserForm()

    try:
        if request.method == "POST" and form.validate_on_submit():
            email = form.email.data
            username = form.username.data
            password = form.password.data
            hashPassword = bcrypt.generate_password_hash(password).decode("utf-8")
            role = form.role.data
            createDate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            
            user = AddUser(email, username, hashPassword, role, createDate)
            userDB.insert_one(user.exportAddUserInfo())

            resetMsg = Message("Notice Email", sender = "kunursinghome@gmail.com", recipients = [email])
            resetToken = resetSeacret.dumps(email).decode('utf-8')
            resetLink = url_for('resetPasswordPage', resetToken = resetToken, _external = True)
            resetMsg.body = "Welcom to Our Website \nYour Account is " + email + "\nPlease Reset Your Own Password With the Link, If You Have No the Password " + resetLink 
            mail.send(resetMsg)

            flash("User Added")
            return redirect(url_for('managerPage'))
        return render_template('AddUser.html', form = form)
    except:
        abort(500)

#Form For Edit User
class EditUserForm(FlaskForm):
    email = StringField("Email", [InputRequired(), validators.Regexp("^[a-zA-Z0-9]+@[a-zA-Z]+\.(com|net|edu|org){1,39}$", message = "Please input a valid email")])
    username = StringField("Username", [InputRequired(), validators.Regexp("^(?!.*[!@#$%^&*])[A-Za-z\d]{7,15}$", message = "Please input a valid Username and at least 8 characters")])
    password = PasswordField("Password", [validators.Optional(), validators.Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{11,15}$", message = "Must at least a number, a letter and a special characters and at least 12 characters")])
    role = SelectField("Role", choices = [("Manager", "Manager"), ("Admin", "Admin"), ("Guest", "Guest")])
    editUserBtn = SubmitField("Submit")


    #If Null then Pass
    def __call__(FlaskForm, password):
        if not password.raw_data:
            raise validators.StopValidation()

#Edit User Page
@app.route("/Manager/EditUser/<id>", methods = ["GET", "POST"])
def editUserPage(id):
    if session.get("role") != "Manager":
        return redirect(url_for("loginPage"))

    form = EditUserForm()
    try:
        if request.method == "POST" and form.validate_on_submit():
            email = form.email.data
            username = form.username.data
            password = form.password.data
            role = form.role.data
            modifyDate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

            if password != "":
                hashPassword = bcrypt.generate_password_hash(password).decode("utf-8")
            if password == "":
                userDB.update_one({"_id" : id}, {"$set" : {"email" : email, "username" : username, "role" : role, "last_modified_time" : modifyDate}})
                flash("Updated")
                return redirect(url_for('managerPage'))
            else:
                userDB.update_one({"_id" : id}, {"$set" : {"email" : email, "username" : username, "password" : hashPassword, "role" : role, "last_modified_time" : modifyDate}})
                flash("Updated")
                return redirect(url_for('managerPage'))

        else:
            user = userDB.find_one({"_id" : id})
            form.email.data = user["email"]
            form.username.data = user["username"]
            form.role.data = user["role"]
        return render_template('EditUser.html', form = form, id = id)
    except:
        abort(500)
        

#Delete User Page
@app.route("/Manager/DeleteUser/<id>", methods = ["POST"])
def delUserPage(id):
    if session.get("role") != "Manager":
        return redirect(url_for("loginPage"))
        
    userDB.delete_one({"_id" : id})
    flash("Deleted")
    return redirect(url_for('managerPage'))


#Home page.................................................................................................................................................................................

@app.route("/", methods = ["GET", "POST"])
def main():
    return render_template("home.html")

@app.route("/home")
def home():
    return render_template("home.html")    

#Login Page..................................................................................................................................................................................
@app.route("/login", methods = ["GET", "POST"])
def loginPage():
    
    logout()
    form = LoginForm()
    errorMsg = []

    try:    
        if request.method == "POST" and form.validate_on_submit():
            email = form.email.data  
            password = form.password.data
            loginUser = userDB.find_one({"email" : email})
            
            if loginUser:
                if loginUser["activate"] == False and bcrypt.check_password_hash(loginUser["password"], password):

                    activateMsg = Message("Activation Email", sender = "kunursinghome@gmail.com", recipients = [email])
                    activateToken = emailSeacret.dumps(email, salt = "Email-Activate-Salt")
                    activateLink = url_for('activateEmail', activateToken = activateToken, _external = True)
                    activateMsg.body = "The activation Link is " + activateLink 
                    mail.send(activateMsg)

                    flash("Please Activate Your Account First")
                    flash("The Activation Email Sent to You Again")
                    return render_template("login.html", form = form, errorMsg = errorMsg)
                if loginUser and bcrypt.check_password_hash(loginUser["password"], password):
                    session["username"] = loginUser["username"]
                    session["role"] = loginUser["role"]
                    session["email"] = loginUser["email"]
                    session["logged in"] = True
                    if session.get("role") == "Manager":
                        return redirect(url_for("managerPage"))
                    if session.get("role") == "Admin":
                        return render_template("admin_home.html")
                    if session.get("role") == "Elderly":
                        list = loadingElderlyHomeData(loginUser["email"])
                        return render_template("elderly_home.html", list = list)
                    if session.get("role") == "Guest":
                        return render_template("guest_home.html")
                else:
                    flash("Credentials Incorrect")
            else:
                flash("Credentials Incorrect")
        return render_template("login.html", form = form, errorMsg = errorMsg)
    except:
        abort(500)

#Request Reset Password Page
@app.route("/login/RequestResetPassword", methods = ["GET", "POST"])
def requestResetPasswordPage():
    if session.get("logged in") == True:
        return redirect(url_for("loginPage"))

    form = RequestResetPassword()
    
    try:
        if request.method == "POST" and form.validate_on_submit():
            email = form.email.data
            user = userDB.find_one({"email" : email})

            if user:
                resetMsg = Message("Reset Password Email", sender = "kunursinghome@gmail.com", recipients = [email])
                resetToken = resetSeacret.dumps(email).decode('utf-8')
                resetLink = url_for('resetPasswordPage', resetToken = resetToken, _external = True)
                resetMsg.body = "The Reset Password Link is " + resetLink 
                mail.send(resetMsg)

                flash("The Reset Password Link Sent To Your Email Address")
                return redirect(url_for("loginPage"))
            else:
                flash("The Reset Password Link Sent To Your Email Address")
                return redirect(url_for("loginPage"))
        return render_template('RequestResetPassword.html', form = form)
    except:
        abort(500)



#Register Page..................................................................................................................................................................................
@app.route("/register", methods = ["GET", "POST"])
def registerPage():
    form = RegisterForm()

    try:
        if request.method == "POST" and form.validate_on_submit():
            email = form.email.data
            username = form.username.data
            password = form.password.data
            hashPassword = bcrypt.generate_password_hash(password).decode("utf-8")
            createDate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

            user = User(email, username, hashPassword, createDate)
            userDB.insert_one(user.exportRegisterUserInfo())
            
            activateMsg = Message("Activation Email", sender = "kunursinghome@gmail.com", recipients = [email])
            activateToken = emailSeacret.dumps(email, salt = "Email-Activate-Salt")
            activateLink = url_for('activateEmail', activateToken = activateToken, _external = True)
            activateMsg.body = "The activation Link is " + activateLink 
            mail.send(activateMsg)

            flash("Register Success")
            flash("The Activation Email Sent to Your Email")
            return redirect(url_for('loginPage'))
        return render_template("register.html", form = form)
    except:
        abort(500)



#Page Activate User
@app.route("/activate/<activateToken>")
def activateEmail(activateToken):
    form = ActivateForm()

    try:
        modifyDate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        email = emailSeacret.loads(activateToken, salt = "Email-Activate-Salt", max_age = 3600)
        userDB.update_one({"email" : email}, {"$set" : {"activate" : True}})
        userDB.update_one({"email" : email}, {"$set" : {"last_modified_time" : modifyDate}})

        flash("User Activated")
        return redirect(url_for('loginPage'))
    except SignatureExpired:
        flash("The Token is Expired")
        return redirect(url_for('loginPage'))
    except:
        abort(500)


@app.route("/signup")
def signup():
    return render_template("signup.html")

#User Class..................................................................................................................................................................................

class User:
    #Constructor
    def __init__(self, email, username, password, createDate):
        self.email = email
        self.username = username
        self.password = password
        self.createDate = createDate
    
    #Export UserInfo
    def exportRegisterUserInfo(self):
        userInfo = {
            "_id" : uuid.uuid4().hex,
            "email" : self.email,
            "username" : self.username,
            "password" : self.password,
            "role" : 'Guest',
            "activate" : False,
            "create_time" : self.createDate,
            "last_modified_time" : self.createDate
        }
        return userInfo

class AddUser:
    #Constructor
    def __init__(self, email, username, password, role, createDate):
        self.email = email
        self.username = username
        self.password = password
        self.role = role
        self.createDate = createDate

    #Export Adding User UserInfo
    def exportAddUserInfo(self):
        userInfo = {
            "_id" : uuid.uuid4().hex,
            "email" : self.email,
            "username" : self.username,
            "password" : self.password,
            "role" : self.role,
            "activate" : True,
            "create_time" : self.createDate,
            "last_modified_time" : self.createDate
        }
        return userInfo

class ElderlyUser:
    #Constructor
    def __init__(self, email, username,room_no, password, otherInfo, createDate):
        self.email = email
        self.username = username
        self.room_no = room_no
        self.password = password
        self.otherInfo = otherInfo
        self.createDate = createDate    

    #Export UserInfo(Elder)
    def exportadminRegisterUserInfo(self):
        userInfo = {
            "_id" : uuid.uuid4().hex,
            "email" : self.email,
            "username" : self.username,
            "room_no" : self.room_no,
            "password" : self.password,
            "otherInfo" : self.otherInfo,
            "role" : 'Elderly',
            "activate" : True,
            "create_time" : self.createDate,
            "last_modified_time" : self.createDate
        }
        return userInfo

#Admin Page Part...............................................................................................................................................................

@app.route("/admin")
def admin_home():
    if "role" in session:
        if session["role"] == "Admin" :
            email = session["email"]
            return render_template("admin_home.html")
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))

#Admin Activity...................................................
@app.route("/admin/admin_activity" , methods = ["GET", "POST"])
def admin_activity():
    if "role" in session:
        if session["role"] == "Admin":
            form = activityForm()
            activityList = loadingActivityList()
            list = [""]
            try:
                if request.method == "POST":
                    if request.form.get("createBtn"):
                        activityNo = form.activityNo.data
                        form.activityNo.data = ""
                        activityName = form.name.data
                        form.name.data = ""
                        activityDate = request.form["activitydate"]
                        activityTime = request.form["activitytime"]
                        activityPlace = form.place.data
                        form.place.data = ""
                        activityDatetail = form.detail.data
                        form.detail.data = ""
                        if checkingActivityNo(activityNo) == True:
                            flash("You have input an existing activity No.")
                        else:
                            insertActivity(activityNo, activityName, activityDate, activityTime, activityPlace, activityDatetail)
                            activityList = loadingActivityList()
                            flash("You have seccussfully created the Activity.")
                        return render_template("admin_activity.html", form = form, list1 = activityList, list2 = list)
                    if request.form.get("updateBtn"):
                        activityNo = form.activityNo.data
                        form.activityNo.data = ""
                        activityName = form.name.data
                        form.name.data = ""
                        activityDate = request.form["activitydate"]
                        activityTime = request.form["activitytime"]
                        activityPlace = form.place.data
                        form.place.data = ""
                        activityDatetail = form.detail.data
                        form.detail.data = ""
                        if checkingActivityNo(activityNo) == False:
                            flash("You have input a wrong activity No. Please check the Activity List.")
                        else:
                            updateActivity(activityNo, activityName, activityDate, activityTime, activityPlace, activityDatetail)
                            activityList = loadingActivityList()
                            flash("You have seccussfully updated the Activity.")
                        return render_template("admin_activity.html", form = form, list1 = activityList, list2 = list)
                    if request.form.get("delBtn"):
                        del_activityNo = form.del_activityNo.data
                        form.del_activityNo.data = ""
                        if checkingActivityNo(del_activityNo) == False:
                            flash("You have input a wrong activity No. Please check the Activity List.")
                        else:
                            deleteActivity(del_activityNo)
                            activityList = loadingActivityList()
                            flash("You have seccussfully deleted the Activity.")
                        return render_template("admin_activity.html", form = form, list1 = activityList, list2 = list)
                    if request.form.get("checkBtn"):
                        check_activityNo = form.check_activityNo.data
                        form.check_activityNo.data = ""
                        if checkingActivityNo(check_activityNo) == False:
                            flash("You have input a wrong activity No. Please check the Activity List.")
                        else:
                                list = loadingActivityAppliedList(check_activityNo)
                        return render_template("admin_activity.html", form = form, list1 = activityList, list2 = list)
                return render_template("admin_activity.html", form = form, list1 = activityList, list2 = list)
            except:
                abort(500)
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))

def checkingActivityNo(activityNo):
    mycol = activityDB.find({"activityNo" : activityNo})
    exist = False
    for x in mycol:
        if x["activityNo"] == activityNo:
            exist = True
    return exist

def insertActivity(activityNo, activityName, activityDate, activityTime, activityPlace, activityDatetail):
    newActivity = {"activityNo" : activityNo, "activityName" : activityName , "activityDate" : activityDate , "activityTime" : activityTime, "activityPlace" : activityPlace, "activityDatetail" : activityDatetail}
    activityDB.insert_one(newActivity)

def updateActivity(activityNo, activityName, activityDate, activityTime, activityPlace, activityDatetail):
    myquery = {"activityNo" : activityNo}
    newvalues = { "$set": { "activityName" : activityName , "activityDate" : activityDate , "activityTime" : activityTime, "activityPlace" : activityPlace, "activityDatetail" : activityDatetail} }
    activityDB.update_one(myquery, newvalues)

def deleteActivity(activityNo):
    activityDB.delete_one({"activityNo" : activityNo})
    activityAppliedDB.delete_many({"activityNo" : activityNo})

def loadingActivityList():
    mycol = activityDB.find({}).sort("activityDate" , 1)
    list = []
    for x in mycol:
        list = list + [[x["activityNo"], x["activityName"], x["activityDate"], x["activityTime"], x["activityPlace"], x["activityDatetail"]]]
    return list

def loadingActivityAppliedList(activityNo):
    mycol = activityAppliedDB.find({"activityNo" : activityNo}).sort("room_no", 1)
    list = []
    for x in mycol:
        list = list + [[x["activityNo"], x["activityName"], x["username"], x["room_no"], x["status"]]]
    return list

#Admin Bill...................................................
@app.route("/admin/admin_bill" , methods = ["GET", "POST"])
def admin_bill():
    if "role" in session:
        if session["role"] == "Admin":
            form = billForm()
            list = loadingElderlyListData()
            checkinglist = []
            try:
                if request.method == "POST":
                    if request.form.get("submitBtn"):
                        email = form.email.data
                        form.email.data = ""
                        month = request.form["month"]
                        amount = form.price.data
                        form.price.data = ""
                        if checkingElderlyEmail(email) == False:
                            flash("You have input the wrong Email.")
                        elif checkingBillExisting(email , month) == True:
                            flash("The bill is existing.")
                        else:
                            insertBill(email, month, amount)
                            flash("The bill is successfully submitted.")
                        return render_template("admin_bill.html", form = form, list1 = list, list2 = checkinglist)
                    if request.form.get("updateBtn"):
                        email = form.up_email.data
                        form.up_email.data = ""
                        month = request.form["up_month"]
                        amount = form.up_price.data
                        form.price.data = ""
                        status = request.form["status"]
                        if checkingElderlyEmail(email) == False:
                            flash("You have input the wrong Email.")
                        elif checkingBillExisting(email , month) == False:
                            flash("The bill does not exist.")
                        else:
                            upadateBill(email, month, amount, status)
                            flash("The bill is successfully updated.")
                        return render_template("admin_bill.html", form = form, list1 = list, list2 = checkinglist)
                    if request.form.get("delBtn"):
                        email = form.del_email.data
                        form.del_email.data = ""
                        month = request.form["del_month"]
                        if checkingElderlyEmail(email) == False:
                            flash("You have input the wrong Email.")
                        elif checkingBillExisting(email , month) == True:
                            delBill(email , month)
                            flash("The bill is successfully deleted.")
                        return render_template("admin_bill.html", form = form, list1 = list, list2 = checkinglist)
                    if request.form.get("checkBtn"):
                        email = form.check_email.data
                        form.check_email.data = ""
                        checkinglist = checkingBillList(email)
                        return render_template("admin_bill.html", form = form, list1 = list, list2 = checkinglist)
                return render_template("admin_bill.html", form = form, list1 = list, list2 = checkinglist)
            except:
                abort(500)
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))

def checkingElderlyEmail(email):
    mycol = userDB.find({"role" : "Elderly"}).sort("room_no" , 1)
    exist = False
    for x in mycol:
        if x["email"] == email:
            exist = True
    return exist

def checkingBillExisting(email , month):
    mycol = billDB.find({"email" : email})
    exist = False
    for x in mycol:
        if x["month"] == month:
            exist = True
    return exist

def insertBill(email , month , amount):
    newBill = {"email" : email, "month" : month , "amount" : amount , "status" : "Not Paid"}
    billDB.insert_one(newBill)

def upadateBill(email, month, amount, status):
    myquery = {"email" : email, "month" : month}
    newvalues = { "$set": { "amount" : amount , "status" : status} }
    billDB.update_one(myquery, newvalues)

def delBill(email , month):
    billDB.delete_one({"email" : email, "month" : month})

def checkingBillList(email):
    mycol = billDB.find({"email" : email}).sort("month" , 1)
    checkingUser = userDB.find({"email" : email})
    for x in checkingUser:
        name = x["username"]
        room_no = x["room_no"]
    list = []
    for x in mycol:
        list = list + [[name, room_no, x["month"], x["amount"], x["status"]]]
    return list

def loadingElderlyListData():
    mycol = userDB.find({"role" : "Elderly"}).sort("room_no" , 1)
    list = []
    for x in mycol:
        list = list + [[x["username"], x["room_no"], x["email"]]]
    return list

@app.route("/admin/admin_account")
def admin_account():
    return render_template("admin_account.html")

#Admin Booking.................................................
@app.route("/admin/admin_booking")
def admin_booking():
    if "role" in session:
        if session["role"] == "Admin":
            form = uniForm()
            list = adminBookingloadingData()
            return render_template("admin_booking.html", list = list, form = form)
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))

@app.route("/admin/admin_booking", methods = ["POST"])
def getAdminValue():
    if "role" in session:
        if session["role"] == "Admin":
            form = uniForm()
            date = request.form["bookingDate"]
            time = request.form["bookingTime"]
            guestEmail = request.form["guestEmail"]
            elderlyName = request.form["elderly_name"]
            status =  request.form["bookingStatus"]
            #Check the correct input data - bookingDate and Time
            if adminBookingcheckingDateTime(date, time) == False:
                flash("You have input the wrong Date and Time.")
            elif adminBookingcheckingName(date, time, guestEmail, elderlyName) == False:
                flash("You have input the wrong Guest Name or Elderly Name.")
            else:
                adminBookingupdateData(date, time, guestEmail, elderlyName, status)
                flash("You have successfully approved / rejected the booking.")
            list = adminBookingloadingData()
            return render_template("admin_booking.html", list = list, form = form)
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))

def adminBookingloadingData():
    #mycol = mydb["bookingTable"]
    mycol2 = bookingDB.find({}).sort("bookingDate" , 1)
    list = []
    for x in mycol2:
        list = list + [[x["guestUsername"], x["guestEmail"], x["elderlyName"], x["elderlyRoomNo"], x["bookingDate"], x["bookingTime"], x["bookingType"], x["bookingStatus"]]]
        #list = list + [[x["elderlyName"], x["bookingDate"], x["bookingTime"], x["bookingType"], x["bookingStatus"]]]
    return list

def adminBookingcheckingDateTime(date, time):
    #mycol = mydb["bookingTable"]
    correct = False
    for x in bookingDB.find({"bookingDate" : date}):
        if x["bookingTime"] == time:
            correct = True
    return correct

def adminBookingcheckingName(date, time, guestEmail, elderlyName):
    #mycol = mydb["bookingTable"]
    correct = False
    for x in bookingDB.find({"bookingDate" : date}):
        if x["bookingTime"] == time:
            if x["guestEmail"] == guestEmail:
                if x["elderlyName"] ==elderlyName:
                    correct = True
    return correct

def adminBookingupdateData(date, time, guestEmail, elderlyName, status):
    #mycol = mydb["bookingTable"]

    myquery = {"guestEmail" : guestEmail, "elderlyName" : elderlyName, "bookingDate" : date, "bookingTime" : time}
    newvalues = { "$set": { "bookingStatus" : status } }
    
    bookingDB.update_one(myquery, newvalues)
    return True

#Admin Elderly Account Management.................................................
@app.route("/admin/admin_register", methods = ["GET", "POST"])
def admin_register():
    if "role" in session:
        if session["role"] == "Admin":
            form = adminRegisterForm()
            list = loadingElderlyUserData()

            try:
                if request.method == "POST":
                    if request.form.get("registerBtn"):
                        email = form.email.data
                        form.email.data = ""
                        username = form.username.data
                        form.username.data = ""
                        room_no = form.room_no.data
                        form.room_no.data = ""
                        password = form.password.data
                        otherInfo = form.otherInfo.data
                        form.otherInfo.data = ""
                        createDate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")                    
                        #check the email exist
                        if checkingEmailExist(email) == False:
                            hashPassword = bcrypt.generate_password_hash(password).decode("utf-8")
                            user = ElderlyUser(email, username, room_no, hashPassword, otherInfo, createDate)
                            userDB.insert_one(user.exportadminRegisterUserInfo())
                            flash("You have seccussfully created an elderly account")
                            list = loadingElderlyUserData()
                            return render_template("admin_register.html", form = form, list = list)
                        else:
                            flash("The email is existing.")
                            list = loadingElderlyUserData()
                            return render_template("admin_register.html", form = form, list = list)
                    elif request.form.get("updateBtn"): 
                        email = form.email.data
                        username = form.username.data
                        room_no = form.room_no.data
                        otherInfo = form.otherInfo.data
                        #check email exist
                        if checkingElderlyEmailExist(email) == False:
                            flash("You have input a wrong email.")
                            list = loadingElderlyUserData()
                            return render_template("admin_register.html", form = form, list = list)
                        else:                            
                            myquery = {"email" : email}
                            newvalues = { "$set": { "username" : username, "room_no" : room_no, "otherInfo" : otherInfo} }
                            userDB.update_one(myquery, newvalues)
                            flash("You have seccussfully updated an elderly account")
                            list = loadingElderlyUserData()
                            return render_template("admin_register.html", form = form, list = list)
                    elif request.form.get("delBtn"):
                        del_email = form.del_email.data
                        form.del_email.data = ""
                        #check email exist
                        if checkingElderlyEmailExist(del_email) == False:
                            flash("You have input a wrong email.")
                            list = loadingElderlyUserData()
                            return render_template("admin_register.html", form = form, list = list)
                        else:
                            userDB.delete_one({"email" : del_email})
                            flash("You have seccussfully deleted an elderly account.")
                            list = loadingElderlyUserData()
                            return render_template("admin_register.html", form = form, list = list)
                return render_template("admin_register.html", form = form, list = list)
            except:
                abort(500)
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))

def loadingElderlyUserData():
    mycol = userDB.find({"role" : "Elderly"}).sort("room_no", 1)
    list = []
    for x in mycol:
        list = list + [[x["email"], x["username"], x["room_no"], x["otherInfo"]]]
    return list 

def checkingElderlyEmailExist(email):
    mycol = userDB.find({"email" : email})
    exist = False
    for x in mycol:
        if x["role"] == "Elderly":
            exist = True
    return exist

def checkingEmailExist(email):
    mycol = userDB.find({"email" : email})
    exist = False
    for x in mycol:
        exist = True
    return exist

#Guest Page Part...............................................................................................................................................................

@app.route("/guest")
def guest_home():
    if "role" in session:
        if session["role"] == "Guest" :
            email = session["email"]
            return render_template("guest_home.html")
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))

@app.route("/guest/guest_booking/")
def guest_booking():
    if "role" in session:
        if session["role"]  == "Guest":
            guestEmail = session["email"]

            form = uniForm()

            list = guestBookingloadingData(guestEmail)
            return render_template("guest_booking.html", list = list, form = form)
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))
    

@app.route("/guest/guest_booking/", methods = ["POST"])
def getvalue():
    if "role" in session:
        if session["role"]  == "Guest":
            guestEmail = session["email"]
            guestUsername = session["username"]

            form = uniForm()

            if request.form["btn"] == "Booking":               
                name = request.form["elderly_name"]
                roomNo = request.form["elderly_room"]
                date = request.form["bookingDate"]
                time = request.form["bookingTime"]
                bookingtype = request.form["bookingType"]
                #Check the correct input data - elderly name & roomNo.
                if guestBookingcompareElderlyData(name, roomNo) == False:
                    flash("You have input the wrong Elderly Name or Elderly Room No.")
                elif guestBookingcheckingDate(date) == False:
                    flash("You have input the wrong Booking Date.")
                elif guestBookingcheckingSameData(guestEmail, name, roomNo, date, time, bookingtype) == True:
                    flash("You have input the same data.")
                elif guestBookingcheckingRepeatBooking(guestEmail, date) == True:
                    flash("You have submitted 3 bookings in the same date.")
                else:
                    #saving booking data to DB
                    guestBookinginputdata(guestUsername, guestEmail, name, roomNo, date, time, bookingtype)
                    flash("You have successfully submitted the booking. We will approve your submission in 3 working days.")
                list = guestBookingloadingData(guestEmail)
                return render_template("guest_booking.html", list = list, form = form)
            elif request.form["btn"] == "Delete":
                name = request.form["del_elderly_name"]
                date = request.form["del_bookingDate"]
                time = request.form["del_bookingTime"]
                bookingtype = request.form["del_bookingType"]
                #check the data correct or not
                if guestBookingcheckingRecord(guestEmail, name, date, time, bookingtype) == False:
                    flash("Please check the booking record below and input the correct data.")
                else:
                    #delete Data from DB
                    guestBookingdeleteData(guestEmail, name, date, time, bookingtype)
                    flash("You have successfully deleted the record.")
                list = guestBookingloadingData(guestEmail)
                return render_template("guest_booking.html", list = list, form = form)
                
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))

def guestBookinginputdata(gusetUsername, guestEmail, inputElderlyName, inputElderlyRoomNo, inputDate, inputTime, bookingType):
    #mycol = mydb["bookingTable"]
    elderlyEmail = guestBookingfindElderlyEmail(inputElderlyName, inputElderlyRoomNo)
    newBooking = {'guestUsername' : gusetUsername, 'guestEmail' : guestEmail, 'elderlyEmail' : elderlyEmail, 'elderlyRoomNo' : inputElderlyRoomNo, 'elderlyName' : inputElderlyName, 'bookingDate' : inputDate, 'bookingTime' : inputTime, 'bookingType' : bookingType, 'bookingStatus' : 'Waiting for approving'}
    bookingDB.insert_one(newBooking)
    return True

def guestBookingdeleteData(guestEmail, name, date, time, bookingtype):
    #mycol = mydb["bookingTable"]
    bookingDB.delete_one({'guestEmail' : guestEmail, 'elderlyName' : name,'bookingDate' : date, 'bookingTime' : time, 'bookingType' : bookingtype})
    return True

def guestBookingfindElderlyEmail(inputName, inputRoomNo):
    #mycol = mydb["userTable"]
    email = ""
    for x in userDB.find({"username" : inputName, "role" : "Elderly"}):
        if x["room_no"] == inputRoomNo:
            email = x["email"]      
    return email

def guestBookingcompareElderlyData(inputName, inputRoomNo):
    #mycol = mydb["userTable"]
    correct = False
    for x in userDB.find({"username" : inputName, "role" : "Elderly"}):
        if x["room_no"] == inputRoomNo:
            correct = True      
    return correct

today = datetime.strptime(str(date.today()), "%Y-%m-%d")
def guestBookingcheckingDate(date):
    inputDate = datetime.strptime(date, "%Y-%m-%d")
    return today<=inputDate

def guestBookingcheckingRepeatBooking(guestEmail, date):
    #mycol = mydb["bookingTable"]
    repaet = False
    count = 0
    for x in bookingDB.find({'guestEmail' : guestEmail}):
        if x["bookingDate"] == date:
            count = count + 1
    if count>2:
        repaet = True
    return repaet

def guestBookingloadingData(guestEmail):
    #mycol = mydb["bookingTable"]
    mycol2 = bookingDB.find({'guestEmail' : guestEmail}).sort("bookingDate" , 1)
    list = []
    for x in mycol2:
        if guestEmail == x["guestEmail"]:
            list = list + [[x["elderlyName"], x["bookingDate"], x["bookingTime"], x["bookingType"], x["bookingStatus"]]]
    return list

def guestBookingcheckingSameData(guestEmail, name, roomNo, date, time, bookingtype):
    same = False
    #mycol = mydb["bookingTable"]
    for x in bookingDB.find({'guestEmail' : guestEmail}):
        if x["elderlyName"] == name:
            if x["elderlyRoomNo"] == roomNo:
                if x["bookingDate"] == date:
                    if x["bookingTime"] == time:
                        if x["bookingType"] == bookingtype:
                            same = True
    return same

def guestBookingcheckingRecord(guestEmail, name, date, time, bookingtype):
    correct = False
    #mycol = mydb["bookingTable"]
    for x in bookingDB.find({'guestEmail' : guestEmail}):
        if x["elderlyName"] == name:
            if x["bookingDate"] == date:
                if x["bookingTime"] == time:
                    if x["bookingType"] == bookingtype:
                        correct = True
    return correct


#Elderly Page Part...............................................................................................................................................................

#Elderly Home...........................................................................................
@app.route("/elderly")
def elderly_home():
    if "role" in session:
        if session["role"] == "Elderly" :
            email = session["email"]
            #showing Visit Booking            
            list = loadingElderlyHomeData(email)            
            return render_template("elderly_home.html", list = list)
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))

def loadingElderlyHomeData(email):
    mycol = bookingDB.find({"elderlyEmail" : email}).sort("bookingDate" , 1)
    list = []
    for x in mycol:
        if x["bookingStatus"] == "Approved":
            list = list + [[x["guestUsername"], x["bookingDate"], x["bookingTime"], x["bookingType"]]]
    return list

#Elderly Personal Data...........................................................................................
@app.route("/elderly/elderly_personalData")
def elderly_personalData():
    if "role" in session:
        if session["role"] == "Elderly" :
            email = session["email"]
            list = loadingElderlyPersonalData(email)
            return render_template("elderly_personalData.html", list = list)
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))

def loadingElderlyPersonalData(email):
    mycol = userDB.find({"role" : "Elderly"}).sort("room_no", 1)
    list = []
    for x in mycol:
        if x["email"] == email:
            list = list + [[x["email"], x["username"], x["room_no"], x["otherInfo"]]]
    return list 

#Elderly Activity...........................................................................................
@app.route("/elderly/elderly_activity", methods = ["GET", "POST"])
def elderly_activity():
    if "role" in session:
        if session["role"] == "Elderly" :
            email = session["email"]
            elderlyName = session["username"]
            elderly_room = findRoomNo(email)
            list = elderlyLoadingActivityAppliedList(email)
            form = elderlyActivity()
            try:
                if request.method == "POST":
                    if request.form.get("joinBtn"):
                        activityNo = form.activityNo.data            
                        form.activityNo.data = ""
                        status = "Join"
                        #check input activity No
                        if checkingActivityNo(activityNo) == False:
                            flash("You have input a wrong activity No.")
                        #check exciting data in activityAppliedTable
                        elif checkingDataInAppliedTable(activityNo, elderlyName, elderly_room) == True:
                            activityName = findActivityName(activityNo)
                            updateElderlyActivityAppliedData(activityNo, activityName, elderlyName, elderly_room, status)
                            flash("You have seccussfully joined the activity.")                
                        else:
                            activityName = findActivityName(activityNo)
                            insertElderlyActivityAppliedData(activityNo, activityName, elderlyName, elderly_room, status)
                            flash("You have seccussfully joined the activity.")
                        list = elderlyLoadingActivityAppliedList(email)
                        return render_template("elderly_activity.html", form = form, list = list)
                    if request.form.get("rejectBtn"):
                        activityNo = form.activityNo.data            
                        form.activityNo.data = ""
                        status = "Reject"
                        #check input activity No
                        if checkingActivityNo(activityNo) == False:
                            flash("You have input a wrong activity No.")
                        #check exciting data in activityAppliedTable
                        elif checkingDataInAppliedTable(activityNo, elderlyName, elderly_room) == True:
                            activityName = findActivityName(activityNo)
                            updateElderlyActivityAppliedData(activityNo, activityName, elderlyName, elderly_room, status)
                            flash("You have seccussfully rejected the activity.")                
                        else:
                            activityName = findActivityName(activityNo)
                            insertElderlyActivityAppliedData(activityNo, activityName, elderlyName, elderly_room, status)
                            flash("You have seccussfully rejected the activity.")
                        list = elderlyLoadingActivityAppliedList(email)
                        return render_template("elderly_activity.html", form = form, list = list)
                return render_template("elderly_activity.html", form = form, list = list)
            except:
                abort(500)
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))
    

def insertElderlyActivityAppliedData(activityNo, activityName, elderlyName, elderly_room, status):
    newActivity = {"activityNo" : activityNo, "activityName" : activityName , "username" : elderlyName , "room_no" : elderly_room, "status" : status}
    activityAppliedDB.insert_one(newActivity)

def updateElderlyActivityAppliedData(activityNo, activityName, elderlyName, elderly_room, status):
    myquery = {"activityNo" : activityNo, "activityName" : activityName , "username" : elderlyName , "room_no" : elderly_room}
    newvalues = { "$set": { "status" : status} }
    activityAppliedDB.update_one(myquery, newvalues)

def elderlyLoadingActivityAppliedList(email):
    mycol = activityDB.find({}).sort("activityDate" , -1)
    list = []
    for x in mycol:
        #checking status
        activityNo = x["activityNo"]
        recordInAppliedTable = activityAppliedDB.find({"activityNo" : activityNo})
        status = "Join / Reject"
        for y in recordInAppliedTable:
            if y["status"] == "Join":
                status = "Join"
            else:
                status = "Reject"
        list = list + [[x["activityNo"], x["activityName"], x["activityDate"], x["activityTime"], x["activityPlace"], x["activityDatetail"], status]]
    return list

def checkingDataInAppliedTable(activityNo, elderlyName, elderly_room):
    mycol = activityAppliedDB.find({"activityNo" : activityNo, "username" : elderlyName , "room_no" : elderly_room})
    exist = False
    for x in mycol:
        exist = True
    return exist

def findRoomNo(email):
    mycol = userDB.find({"email" : email})
    for x in mycol:
        elderly_room = x["room_no"]
    return elderly_room

def findActivityName(activityNo):
    mycol = activityDB.find({"activityNo" : activityNo})
    for x in mycol:
        activityName = x["activityName"]
    return activityName

#Elderly Bill...........................................................................................
@app.route("/elderly/elderly_bill")
def elderly_bill():
    if "role" in session:
        if session["role"] == "Elderly" :
            email = session["email"]
            list = loadingElderlyBillData(email)
            return render_template("elderly_bill.html", list = list)
        else:
            logout()
            return redirect(url_for("loginPage"))
    else:
        logout()
        return redirect(url_for("loginPage"))

def loadingElderlyBillData(email):
    userdata = userDB.find({"email" : email})
    for y in userdata:
        name = y["username"]
        room_no = y["room_no"]
    mycol = billDB.find({"email" : email}).sort("month" , 1)
    list = []
    for x in mycol:
        list = list +[[name, room_no, x["month"], x["amount"], x["status"]]]
    return list


#Logout Page Part...............................................................................................................................................................

@app.route("/logout")
def logout():
    logout()
    return redirect(url_for("loginPage"))

def logout():
    session.pop("email" , None)
    session.pop("role" , None)
    session.pop("username" , None)
    session["logged in"] = False

if __name__=="__main__":
    app.run(host='0.0.0.0', ssl_context='adhoc')
#     app.run(debug=True)
    