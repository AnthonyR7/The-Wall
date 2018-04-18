from flask import Flask, request, redirect, render_template, session, flash,url_for
from flask.ext.bcrypt import Bcrypt
from mysqlconnection import MySQLConnector
import re
import md5
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "ThisIsSecret!"
mysql = MySQLConnector(app,'log')
@app.route('/')
def index():
    if "form_data" not in session:
        session["form_data"] = {}
    if "logged_in" in session:
        return redirect("/dashboard")
    return render_template('index.html')
@app.route('/process', methods=['POST'])
def process():
    session["form_data"] = {}
    action = request.form['action']
    form = request.form
    if action == "register":
        errors = []
        if len(request.form['email']) < 1:
            errors.append("Email can not be empty!")

        elif not EMAIL_REGEX.match(request.form['email']):
            errors.append("Invalid Email Address!")

        if len(request.form['f_name']) < 2 :
            errors.append("First Name be more then 2 characters long")

        if len(request.form['l_name']) < 2 :
            errors.append("Last Name be more then 2 characters long")

        if (request.form['f_name'].isalpha()) != True:
            errors.append("Fist Name numbers in First name!",'no_num')

        if (request.form['l_name'].isalpha()) != True:
            errors.append("Last Name numbers in First name!",'no_num')

        if (request.form['pass_word']) < 8:
            errors.append("Pass word must be at least 8 characters in lengh.")

        if (request.form['pass_word']) != (request.form['confirm_password']):
            errors.append("Pass word does not match Confirmation input",'issue')

        if len(errors) == 0:
            query = "INSERT INTO users (first_name,last_name,email,pass_word) VALUES (:first_name,:last_name,:email,:pass_word)"
            data = {
                    'first_name':request.form['f_name'],
                    'last_name':request.form['l_name'],
                    'email': request.form['email'],
                    'pass_word':bcrypt.generate_password_hash(form["pass_word"])
                    }
            mysql.query_db(query, data)
            flash("You have successfully Registered!")
            return redirect('/')
        else:
            for message in errors:
                flash(message)
                return redirect('/')
        return redirect("/")
    elif action == "login":
        errors = []
        if form["login_email"] == "":
            error.append("Email can not be empty.")
        if form["login_password"] == "":
            error.append("Password can not be empty.")
        if len(errors) > 0:
            for message in errors:
                flash(message)
            return redirect("/")
        else:
            query = "SELECT * FROM users WHERE email = :email"
            data = {
                "email":form["login_email"]
            }
            user = mysql.query_db(query, data)
            if len(errors) == 0:
                user = user[0]
                if bcrypt.check_password_hash(user["pass_word"], form["login_password"]):
                    session["logged_in"] = user["id"]
                    return redirect(url_for("success"))
                else:
                    flash("Incorrect password")
            else:
                flash("No user with that email")
            return redirect('/')
@app.route('/success', methods = ['GET','POST'])
def success():
    return render_template('access.html')
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
app.run(debug=True)
