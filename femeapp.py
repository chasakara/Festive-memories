import os
from flask import Flask, redirect, render_template
from flask import flash, url_for, request, session
from flask_pymongo import PyMongo
from flask_ckeditor import CKEditor
from bson.objectid import ObjectId
import datetime
import bcrypt
import re
import math
from os import path
if path.exists("env.py"):
    import env

app = Flask(__name__)

app.config['MONGODB_NAME'] = "festive-memories"
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')


mongo = PyMongo(app)
CKEditor(app)

@app.route('/')
@app.route("/index")
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        users = mongo.db.users
        time = datetime.datetime.now()
        existing_email = users.find_one({'email': request.form['userEmail']})
        if existing_email is None:
            hashpass = bcrypt.hashpw(request.form['userPassword'].
                                     encode('utf-8'), bcrypt.gensalt())
            users.insert({
                'name': request.form['username'].capitalize(),
                'email': request.form['userEmail'].lower(),
                'password': hashpass,
                'user_herbs': [],
                'reg_date': time
            })
            session['username'] = request.form['username']
            session['logged_in'] = True
            flash('Hello' + session['username'] +
                  'You have successfull signedup')
            return redirect(url_for('all_herbs',))
        flash('That email or username already exists')
        return render_template('signup.html')
    return render_template('signup.html')

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        users = mongo.db.users
        time = datetime.datetime.now()
        existing_email = users.find_one({'email': request.form['userEmail']})
        if existing_email is None:
            hashpass = bcrypt.hashpw(request.form['userPassword'].
                                     encode('utf-8'), bcrypt.gensalt())
            users.insert({
                'name': request.form['username'].capitalize(),
                'email': request.form['userEmail'].lower(),
                'password': hashpass,
                'user_herbs': [],
                'reg_date': time
            })
            session['username'] = request.form['username']
            session['logged_in'] = True
            flash('Hello' + session['username'] +
                  'You have successfull signedup')
            return redirect(url_for('all_herbs',))
        flash('That email or username already exists')
        return render_template('signup.html')
    return render_template('signup.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        users = mongo.db.users
        login_user = users.find_one({'email': request.form['userEmail']})
        if login_user:
            if bcrypt.checkpw(request.form['userPassword'].encode('utf-8'),
                              login_user['password']):
                session['username'] = login_user['name']
                session['logged_in'] = True
                flash('Welcome Back ' +
                      session['username'] + ' You are now Logged In')
                return redirect(url_for('index'))
            flash('This Username or Password is invalid')
            return render_template('login.html')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    session['logged_in'] = False
    flash('You are now logged out')
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(error):
    app.logger.info(f'Page not found: {request.url}')
    return render_template('404.html', error=error)

if __name__ == "__main__":
    app.run(host=os.environ.get('IP'),
            port=(os.environ.get('PORT')),
            debug=False)