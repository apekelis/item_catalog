#!/usr/bin/env python
import random
import string
import requests
import json
import httplib2

from flask import session as login_session
from flask import Flask, render_template, make_response
from flask import request, redirect, jsonify, url_for, flash

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, ListItem, User

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

# use pycodestyle to check code for style errors

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Show main page
@app.route('/')
@app.route('/categories/')
def showCategories():
    categories = session.query(Category).order_by(asc(Category.name))
    if 'user_id' in login_session:
        return render_template('categories.html', categories=categories,
                               user=getUserInfo(login_session['user_id']))
    else:
        return render_template('pubcategories.html', categories=categories)


# Show Login page
@app.route('/login')
def showLogin():
    return ''


@app.route('/disconnect')
def disconnect():
    return ''


@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/items')
def showItems(category_id):
    return ''


# Start web-server using a non-threaded server because otherwise i had
# problems with SQLite
if __name__ == '__main__':
    app.secret_key = 'super_califrastico'
    app.debug = True
    app.run(host='0.0.0.0', port=8000, threaded=False)
