from flask import Flask, request, redirect, render_template, session, flash,url_for
from flask.ext.bcrypt import Bcrypt
from mysqlconnection import MySQLConnector
import re
import md5
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "ThisIsSecret!"
mysql = MySQLConnector(app,'facebook')
@app.route('/')
def index():
    if "form_data" not in session:
        session["form_data"] = {}
    if "logged_id" in session:
        print "this is the begining"
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

        if (request.form["username"]) < 0:
            errors.append("username can not be empty.")

        if (request.form['pass_word']) != (request.form['confirm_password']):
            errors.append("Pass word does not match Confirmation input",'issue')

        if len(errors) == 0:
            print "this is the len(errors) == 0 part"
            query = "INSERT INTO users (first_name,last_name,username,email,password) VALUES (:first_name,:last_name,:username,:email,:password)"
            data = {
                    'first_name':request.form['f_name'],
                    'last_name':request.form['l_name'],
                    "username": request.form["username"],
                    'email': request.form['email'],
                    'password':bcrypt.generate_password_hash(form["pass_word"])
                    }
            print "This is the query part"
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
        if form["login_user"] == "":
            error.append("Email can not be empty.")
        if form["login_password"] == "":
            error.append("Password can not be empty.")
        if len(errors) > 0:
            for message in errors:
                flash(message)
            return redirect("/")
        else:
            print "hello world"
            query = "SELECT * FROM users WHERE user = :given_username"
            data = {
                "given_username":form["login_user"]
            }
            user = mysql.query_db(query, data)
            if len(user) > 0:
                user = user[0]
                if bcrypt.check_password_hash(user["pass_word"], form["login_password"]):
                    session["logged_id"] = user["id"]
                    return redirect("/")
                else:
                    flash("Incorrect pass word.")
                    return redirect(url_for("dashboard"))
            else:
                flash("No no user name found.")
            return redirect('/')
@app.route('/dashboard', methods = ['POST'])
def dashboard():
    print ("Hello and welcome to the hard part of using code.")
    query = "SELECT * FROM users WHERE id = :logged_id"
    data = {
        "logged_id": session["logged_id"]
    }
    logged_user = mysql.query_db(query, data)
    return render_template('dashboard.html', current_user = logged_user)
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
app.run(debug=True)
