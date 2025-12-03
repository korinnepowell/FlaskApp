"""Lab 8"""
# Korinne Bubb
# SDEV 300
# lab 8 Final LAB!!:)

from datetime import datetime
import csv
import re
import logging
from passlib.hash import sha256_crypt
from flask import Flask, flash, redirect, render_template, request, url_for


PASSWORD_FILE='passwordFile.csv'
app =  Flask(__name__)  # create/start flask environment
app.secret_key ="ThisIsSecretKey"

# Set up  and configure logging
# Used a .log file since this provides a detailed list of events 
# related to the system
logging.basicConfig(filename='app.log', level=logging.INFO)
logger = logging.getLogger(__name__)

users = {}  # Initialize the users

@app.route('/index.html')  #  app route decorator to set up URL
def index():
    """home page"""
    return render_template('index.html', datetime=str(datetime.now()))
            # this renders a template from
            # template folder with given context


def read_the_file():
    """function to read the file that is created"""
    try:
        with open(PASSWORD_FILE, 'r', encoding="utf-8") as passfile:
            reader = csv.reader(passfile)
            for row in reader:
                users[row[0]] = row[1]
    except FileNotFoundError:
        pass
    return users


def write_user_to_file(username, pass_hash):
    """writing the user to the password file"""
    try:
        with open(PASSWORD_FILE, 'a', newline='' ,encoding="utf-8")as passfile:
            writer = csv.writer(passfile)
            writer.writerow([username, pass_hash])
            return
    except FileNotFoundError:
        logger.error("Could not find file")


def is_common_password(password):
    """Is common password"""
    try: # check list of common passwords
        with open('CommonPassword.txt', 'r',encoding="utf-8") as common_pass_txt:
            common_passwords = [line.strip() for line in common_pass_txt]
    except FileNotFoundError:
        common_passwords = []
    return password in common_passwords


def password_complexity (password):
    """password_complexity function"""
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$'
    return re.match(pattern, password) is not None


def verify_password(login_pass, stored_pass_hash):
    """function used to verify that the passwords are the same"""
    return sha256_crypt.verify(login_pass, stored_pass_hash)


@app.route('/register.html',methods=['POST','GET'])
def register():
    """Registration page"""
    if request.method =="POST":
        #  Retrieves username and passowrd from form
        username = request.form["username"]
        password = request.form["password"]
        users = read_the_file()
        # checks to make sure all criteria is met flashes message if not
        if is_common_password(password):
            flash("Is common password")
            return redirect(url_for('register'))
        if len(username)<4:
            flash("username must be greater than 4 characters")
            return redirect(url_for("register"))
        if password_complexity(password):
            flash("Your password meets the criteria.")
        else:
            flash("Your password does not meet the criteria")
            return redirect(url_for('register'))
        if username in users:
            flash("username already exists")
            return redirect(url_for("register"))
        pass_hash=sha256_crypt.hash(password)
        write_user_to_file(username, pass_hash)
        flash("registration was successful!")
        # Logging new registered users
        logger.info("New User registered: %s", username)
        return redirect(url_for('login'))
    return render_template("register.html")


@app.route('/login.html', methods=['GET','POST'])
#  Login route handles both GET and POST requests
def login():
    """login page"""    
    if request.method=='POST':
        username =request.form['username']
        password = request.form['password']
        #  Retrieves username and password from form
        #  Reads user data from file and will verify user credentials
        users = read_the_file()
        # logs successful and unsuccessful login attempts
        # stores in app.log
        if username in users and verify_password(password, users[username]):
            flash ('login successful...welcome')
            logger.info("User logged in: %s", username)
            return redirect(url_for('index'))
        else:
            flash('login unsuccessful..try again')
            logger.warning("Failed login attempt for user: %s", username)
            return redirect(url_for('register'))
    return render_template('login.html')

def change_user_pass(username, password, new_password):
    """function used to change the users password"""
    # Writes new password to file
    users= read_the_file()
    if username in users and verify_password(password, users[username]):
        new_hashed_password = sha256_crypt.hash(new_password)
        users[username]= new_hashed_password
        write_user_to_file(username, new_hashed_password)
        return True
    else:
        flash("Incorrect old password")
        return False

@app.route('/change_password.html', methods=['GET','POST'])
def change_password():
    """change password page"""
    if request.method =='POST':
        username =request.form['username']
        password = request.form['password']
        new_password= request.form['new_password']
        if change_user_pass(username, password, new_password):
            flash("password change was a success!")
            logger.info("User changed the password:  %s", username)
            return redirect(url_for('login'))
        else:
            flash("changes not made")
            logger.warning("Incorrect password change-FAILED UPDATE:  %s", username)
    return render_template('change_password.html')
        # this page used to change password


@app.route('/pageone.html')
def page_one():
    """page one"""
    return render_template('pageone.html', datetime=str(datetime.now()))
        # this will be the second page


@app.route('/pagetwo.html')
def page_two():
    """page two"""
    return render_template('pagetwo.html', datetime=str(datetime.now()))
        # this will be the second page


@app.route('/pagethree.html')
def page_three():
    """page three"""
    return render_template('pagethree.html', datetime=str(datetime.now()))
        # this will be the third page


@app.route('/table.html')
def table():
    """page with table"""
    return render_template('table.html',datetime=str(datetime.now()))
        # this will be the table page

if __name__ == "__main__":
    app.run(debug=True)  # set debug to true so updates will
