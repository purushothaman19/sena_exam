import smtplib
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
# from forms import CreatePostForm, LoginForm, CommentForm, RegisterForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, URL
from sqlalchemy.orm import relationship
from sqlalchemy import Column, String, Integer, PrimaryKeyConstraint, ForeignKey, create_engine, MetaData
from functools import wraps
from markupsafe import Markup
from datetime import datetime
import random
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///sena.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

admin = False
login_manager = LoginManager()
login_manager.init_app(app)

MY_EMAIL = 'officialpurushothaman@gmail.com'
SENA_EMAIL = 'sivagangainagarajan@gmail.com'
MY_PASSWORD = 'purushoth.g'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.user_id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


class User(UserMixin, db.Model):
    __tablename__ = "User"
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    username = db.Column(db.String(100))

    def get_id(self):
        return self.user_id


class Admission(UserMixin, db.Model):
    __tablename__ = "New_Admission"
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    mobile_number = db.Column(db.Integer)
    email = db.Column(db.String(100), unique=True)


db.create_all()
db.session.commit()

# for i in range(1, 10):
#     users = User.query.get(i)
#     print(users)
#     db.session.delete(users)
#     db.session.commit()


class RegisterForm(FlaskForm):
    name = StringField('Name*', validators=[DataRequired()])
    email = EmailField('Email*', validators=[DataRequired(message='Enter a valid email-id')])
    password = PasswordField('Password*', validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email*', validators=[DataRequired(message='Enter a valid email-id')])
    password = PasswordField('Password*', validators=[DataRequired()])
    submit = SubmitField('Login')


class AdmissionForm(FlaskForm):
    name = StringField('Name*', validators=[DataRequired()])
    number = StringField("Phone*", validators=[DataRequired()])
    email = EmailField('Email*', validators=[DataRequired(message='Enter a valid email-id')])
    submit = SubmitField('Submit')


class ChangeDetails(FlaskForm):
    email = StringField('Email*', validators=[DataRequired(message='Enter a valid email-id')])
    old_password = PasswordField('Old Password*', validators=[DataRequired()])
    new_password = PasswordField('New Password*', validators=[DataRequired()])
    submit = SubmitField('Submit')


student_mails = {
    "mgopalakrishnan075@gmail.com": ["Gopal", 2000],
    "nivir6558@gmail.com": ["Nivetha", 7000],
    "jaya26jj@gmail.com": ["Christy", 7000],
    "srjamuna@gmail.com": ["jamuna", 7000],
    "satheshpandian1997@gmail.com": ["Satheshpandian", 5000],
    "lakshmiraja412@gmail.com": ["Rajalaskhmi", 5000],
    "tamilarasanbe9597@gmail.com": ["Anitha", 1000],
    "rajeshkannan6341@gmail.com": ["Rajesh kannan", 3000],
    "jaishreeramgp@gmail.com": ["Yogapriya", 3000],
    "irudhayasubiksha2001@gmail.com": ["Subiksha", 3000],
    "abinayaabi257@gmail.com": ["Abi", 3000],
    "shanthirasu1991@gmail.com": ["Shanthi", 0],
    "pradee1296@gmail.com": ["Pradeepa", 5000],
    "jeniferj0204@gmail.com": ["Janifer", 7000],
    "Krish47457@gmail.com": ["Krishna", 0],
    "naveenaryan440@gmail.com": ["Naveen", 0],
    "veerasurya250899@gmail.com": ["Suriya", 3000],
    "amin2svg@gmail.com": ["Amin", 3000],
    "jjprincy06@gmail.com": ["Jeba Josepin Princy", 3000],
    "jancybetsia20@gmail.com": ["Jancy", 0],
    "cottonpanju9@gmail.com": ["Panju", 2000],
    "rameswariv1999@gmail.com": ["Rameshwari", 2000],
    "vimaladharmar2002@gmail.com": ["Vimala", 1000],
    "devahi1993@gmail.com": ["Devahi", 0],
    "sarojiniganesan96@gmail.com": ["Sarojini", 0],
    "gangadha91@gmail.com": ["Gangadharan", 0],
    "krishnannk498@gmail.com": ["Kamatchi", 0],
    "indhuindhumathi141@gmail.com": ["Indhumathi", 4000],
    "jamespurysh@gmail.com": ["Purush", 0],
}

verified_emails = [mail.strip() for mail in student_mails.keys()]


@app.route("/", methods=["GET", "POST"])
def home():
    if request.args.get("fee"):
        name = request.args.get("name")
        bending = request.args.get("bending")
        logged_in = request.args.get("logged_in")

        return render_template("index.html", fee=True, name=name, bending=bending, logged_in=logged_in)

    warning = request.args.get("warn")

    return render_template("index.html", warning=warning)


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    errors = []

    if form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )

        new_user = User(
            email=request.form.get('email'),
            username=request.form.get('name'),
            password=hash_and_salted_password,
        )

        if User.query.filter_by(email=request.form.get('email').lower()).first():
            return redirect(url_for('login', msg="You've already been registered. Please Login!"))

        elif User.query.filter_by(username=request.form.get('name')).first():
            errors.append('The username has already been taken')
            return render_template("register.html", errors=errors, form=form)

        else:
            errors.clear()

            if request.form.get('email') in verified_emails:

                with smtplib.SMTP('smtp.gmail.com', 587) as connection:
                    connection.starttls()
                    connection.login(MY_EMAIL, MY_PASSWORD)
                    connection.sendmail(from_addr=MY_EMAIL,
                                        to_addrs=request.form.get('email'),
                                        msg=f"Subject:WELCOME TO SENA CAREER INSTITUTE\n\nWelcome "
                                            f"{request.form.get('name')}! Happy to see you with us."
                                            f" Thanks for supporting us! Keep rocking!".encode('utf-8'))

                db.session.add(new_user)
                db.session.commit()

                login_user(new_user)

                # redirect to the home page with fee details.
                return redirect(url_for('home', fee=True, name=student_mails[request.form.get('email')][0],
                                        bending=student_mails[request.form.get('email')][1]))

            else:
                return redirect(url_for('home', warn=True))

    return render_template("register.html", form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    errors = []

    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')

        # Find user by email entered.
        user = User.query.filter_by(email=email).first()

        if not user:
            errors.append("That email does not exist, please Register and then come back.")
            return render_template("login.html", errors=errors, form=form)

        # Check stored password hash against entered password hashed.
        if check_password_hash(user.password, password):
            login_user(user)
            errors.clear()

            # checking the user's payment details
            # redirect to the home page with fee details.
            return redirect(url_for('home', fee=True, name=student_mails[request.form.get('email')][0],
                                    bending=student_mails[request.form.get('email')][1]))

        else:
            errors.append('Incorrect Password! Try Again')
            return render_template("login.html", errors=errors, form=form)

    msg = request.args.get("msg")
    return render_template("login.html", form=form, errors=errors, msg=msg)


@app.route("/exam")
@login_required
def exam():
    return render_template("exam.html")


@app.route("/admission", methods=["GET", "POST"])
def new_admission():
    form = AdmissionForm()

    if form.validate_on_submit():
        new_member = Admission(
            name=form.name.data,
            mobile_number=form.number.data,
            email=form.email.data,
        )

        db.session.add(new_member)
        db.session.commit()

        # verification_code = random.randint(2000, 10000)

        with smtplib.SMTP('smtp.gmail.com', 587) as connection:
            connection.starttls()
            connection.login(MY_EMAIL, MY_PASSWORD)
            connection.sendmail(from_addr=MY_EMAIL,
                                to_addrs=request.form.get('email'),
                                msg=f"Subject:WELCOME TO SENA CAREER INSTITUTE\n\nWelcome {request.form.get('name')}!"
                                    f" Happy to see you with us. Thanks for supporting us! Keep rocking! "
                                    f"Here is our Educators' number: 8610642720".encode('utf-8'))

        with smtplib.SMTP('smtp.gmail.com', 587) as connection:
            connection.starttls()
            connection.login(MY_EMAIL, MY_PASSWORD)
            connection.sendmail(from_addr=MY_EMAIL,
                                to_addrs=MY_EMAIL,
                                msg=f"Subject:NEW ADMISSION\n\n{request.form.get('name')} has made an "
                                    f"admission sign up on Sena site Here is details {request.form.get('name')},"
                                    f" {request.form.get('number')}, {request.form.get('email')}!")

        # return redirect(url_for('home'))

    return render_template("register.html", form=form, admission=True)


@app.route("/change_details", methods=["GET", "POST"])
def change_password():
    form = ChangeDetails()
    errors = []

    if form.validate_on_submit():
        email = request.form.get('email')
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')

        user = User.query.filter_by(email=email).first()

        if not user:
            errors.append("That email does not exist, please Register and then come back.")
            return render_template("login.html", errors=errors, form=form)

        # Check stored password hash against entered password hashed.
        if check_password_hash(user.password, old_password):

            if User.query.filter_by(email=email).first():
                old = User.query.filter_by(email=email).first()
                pass_to_update = User.query.get(old.user_id)

                hash_and_salted_password = generate_password_hash(
                    new_password,
                    method='pbkdf2:sha256',
                    salt_length=8
                )

                pass_to_update.password = hash_and_salted_password

                db.session.commit()

                logout_user()
                return redirect(url_for('login', msg="Your password has been changed successfully. "
                                                     "Please Login with your new password."))

        else:
            errors.append("Please check your password.")
            return render_template("change_details.html", form=form, errors=errors)

    return render_template("change_details.html", form=form, errors=errors)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
