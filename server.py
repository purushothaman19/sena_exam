import datetime
import smtplib
import pandas
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from sqlalchemy.orm import relationship
from wtforms import StringField, SubmitField, PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired
from functools import wraps
import os
import json

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

MY_EMAIL = os.environ.get("MY_EMAIL")
SENA_EMAIL = 'sivagangainagarajan@gmail.com'
MY_PASSWORD = os.environ.get("MY_PASSWORD")


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
    test = relationship("Test15", back_populates="test_author")

    def get_id(self):
        return self.user_id


# class Admission(db.Model):
#     __tablename__ = "New_Admission"
#     user_id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100))
#     mobile_number = db.Column(db.Integer)
#     email = db.Column(db.String(100), unique=True)

db.create_all()
db.session.commit()


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
    "srjamuna1003@gmail.com": ["jamuna", 7000],
    "satheshpandian1997@gmail.com": ["Satheshpandian", 7000],
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
    "jamespurysh@gmail.com": ["Purushothaman", 0],
    "sivagangainagarajan@gmail.com": ["Nagarajan", 0],
    "matheshsethu22@gmail.com": ["Mathesh", 4000],
    "nagarajnkarthika@gmail.com": ["Karthika", 2000],
    "keviraj482@gmail.com": ["Yogesh", 2000],
}

verified_emails = [mail.strip() for mail in student_mails.keys()]

exam_sites = {
                "13": ["https://drive.google.com/file/d/1rifZhnGAXpVXYL4yqyvsTIsjWhEmcGu7/preview",
                       "May 31, 2021 10:00:00", "May 31, 2021 13:00:00"],

                "14": ["https://drive.google.com/file/d/1MlxFd6JY-W_piE2bklugYNMY6HGB-156/preview",
                       "June 09, 2021 15:56:00", "June 09, 2021 15:54:00"]

              }

file = pandas.read_csv("test-sample.csv")
data = file.to_dict()

sl_no = list(data['Sl.No'].values())
ques = list(data['Question'].values())
a = list(data['A'].values())
b = list(data['B'].values())
c = list(data['C'].values())
d = list(data['D'].values())
correct_answer = list(data['Answer'].values())


@app.route("/", methods=["GET", "POST"])
def home():

    warning = request.args.get("warn")

    if current_user.is_authenticated:

        if request.args.get("fee"):
            name = request.args.get("name")
            bending = request.args.get("bending")
            logged_in = request.args.get("logged_in")

            if Test15.query.filter_by(examinee_id=current_user.user_id).first():
                completed = Test15.query.filter_by(user_id=current_user.user_id).first()
                return render_template("index.html", fee=True, name=name, bending=bending, logged_in=logged_in,
                                       completed=completed)

            else:
                return render_template("index.html", fee=True, name=name, bending=bending, logged_in=logged_in)

        else:
            if Test15.query.filter_by(examinee_id=current_user.user_id).first():
                completed = Test15.query.filter_by(examinee_id=current_user.user_id).first()
                return render_template("index.html", warning=warning, completed=completed)

            else:
                return render_template("index.html", warning=warning)

    else:
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

                # with smtplib.SMTP('smtp.gmail.com', 587) as connection:
                #     connection.starttls()
                #     connection.login(MY_EMAIL, MY_PASSWORD)
                #     connection.sendmail(from_addr=MY_EMAIL,
                #                         to_addrs=request.form.get('email'),
                #                         msg=f"Subject:WELCOME TO SENA CAREER INSTITUTE\n\nWelcome "
                #                             f"{request.form.get('name')}! Happy to see you with us."
                #                             f" Thanks for supporting us! Keep rocking!".encode('utf-8'))

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


@app.route("/exam", methods=["GET", "POST"])
def exam():

    if request.method == "GET" and request.args.get("submit") == "True":
        answers = []
        final_result = []
        marks = 0

        for i in range(0, 3):
            user_answer = request.args.get(f'answers{i}')

            if user_answer is None:
                answers.append("None")

            else:
                answers.append(user_answer)

        for j in range(len(correct_answer)):

            if answers[j] == correct_answer[j]:
                marks += 1
                final_result.append("Correct")

            else:
                final_result.append("Wrong")

        st_answers = '#||#'.join(answers)
        f_result = "#||#".join(final_result)

        new_examinee = Test15(
            test_author=current_user,
            user_answers=st_answers,
            marks=marks,
            final_result=f_result,
            examinee_name=current_user.username,
            date=datetime.datetime.now()
        )

        db.session.add(new_examinee)
        db.session.commit()

        return redirect(url_for('home', warn="You have successfully completed the exam. Click results to see results."))

    else:
        exam_url = exam_sites[request.args.get("test_no")][0]
        opentime = exam_sites[request.args.get("test_no")][1]
        closetime = exam_sites[request.args.get("test_no")][2]

        attended = Test15.query.filter_by(user_id=current_user.user_id).first()

        if attended is None:
            return render_template("exam.html", url=json.dumps(exam_url).replace('"', ''), opentime=json.dumps(opentime),
                                   closetime=json.dumps(closetime), sl_no=sl_no, ques=ques, a=a, b=b, c=c, d=d,
                                   correct_answer=correct_answer, answers=[])
        else:
            return redirect(url_for("home", warn="You have already committed this exam. Check the results instead."))


@app.route("/result", methods=["GET", "POST"])
def result():
    attended_student = Test15.query.filter_by(user_id=current_user.user_id).first()

    answers = attended_student.user_answers.split('#||#')
    final_result = attended_student.final_result.split('#||#')
    marks = attended_student.marks
    time = attended_student.date

    return render_template("results.html", answers=answers, marks=marks,  sl_no=sl_no, ques=ques, a=a, b=b, c=c, d=d,
                           correct_answer=correct_answer, final_result=final_result, time=time)


@app.route("/dashboard")
def dashboard():
    all_record = Test15.query.all()

    return render_template("dashboard.html", all_record=all_record)


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


# @app.route("/admission", methods=["GET", "POST"])
# def new_admission():
#     form = AdmissionForm()
#
#     if form.validate_on_submit():
#         new_member = Admission(
#             name=form.name.data,
#             mobile_number=form.number.data,
#             email=form.email.data,
#         )
#
#         db.session.add(new_member)
#         db.session.commit()

        # verification_code = random.randint(2000, 10000)

        # with smtplib.SMTP('smtp.gmail.com', 587) as connection:
        #     connection.starttls()
        #     connection.login(MY_EMAIL, MY_PASSWORD)
        #     connection.sendmail(from_addr=MY_EMAIL,
        #                         to_addrs=request.form.get('email'),
        #                         msg=f"Subject:WELCOME TO SENA CAREER INSTITUTE\n\nWelcome {request.form.get('name')}!"
        #                             f" Happy to see you with us. Thanks for supporting us! Keep rocking! "
        #                             f"Here is our Educators' number: 8610642720".encode('utf-8'))

        # with smtplib.SMTP('smtp.gmail.com', 587) as connection:
        #     connection.starttls()
        #     connection.login(MY_EMAIL, MY_PASSWORD)
        #     connection.sendmail(from_addr=MY_EMAIL,
        #                         to_addrs=MY_EMAIL,
        #                         msg=f"Subject:NEW ADMISSION\n\n{request.form.get('name')} has made an "
        #                             f"admission sign up on Sena site Here is details {request.form.get('name')},"
        #                             f" {request.form.get('number')}, {request.form.get('email')}!")

    #     return redirect(url_for('home'))
    #
    # return render_template("register.html", form=form, admission=True)


if __name__ == '__main__':
    app.run(debug=True)
