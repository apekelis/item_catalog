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

GO_CLIENT_ID = json.loads(
    open('go_client_secrets.json', 'r').read())['web']['client_id']

FB_CLIENT_ID = json.loads(open('fb_client_secrets.json', 'r').read())[
    'web']['app_id']


# Connect to Database and create database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """Handles Facebook login handshake."""

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token
    app_id = FB_CLIENT_ID
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?'
    url += 'grant_type=fb_exchange_token&client_id=%s&' % (app_id)
    url += 'client_secret=%s&fb_exchange_token=%s' % (app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we
        have to split the token first on commas and select the first index
        which gives us the key : value for the server access token then we
        split it on colons to pull out the actual token value and replace the
        remaining quotes with nothing so that it can be used directly in the
        graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')
    url = 'https://graph.facebook.com/v2.8/me'
    url += '?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'Facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token='
    url += '%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Handles Google sign in Oauth2 handshake."""

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    code = request.data
    try:

        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(
            'go_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 50)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']

    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != GO_CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use, and set provider.
    login_session['access_token'] = credentials.access_token
    login_session['provider'] = "Google"
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Check if user is already in DB
    user_id = getUserID(login_session['email'])

    # If not, create the user in the DB based on the login session
    if not user_id:
        user_id = createUser(login_session)
    # Finally add the user id info to the login session information
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"

    return output


def createUser(login_session):
    """Creates a user in the database, with the "login_session" information."""

    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """Gets a User information from the database using his ID."""

    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """Gets a User ID from the database, using his email."""

    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/fbdisconnect')
def fbdisconnect():
    """Handles Facebook account logout."""

    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    # Only disconnect a connected user.
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    if login_session['provider'] == 'google':
        gdisconnect()
        del login_session['gplus_id']

    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gdisconnect')
def gdisconnect():
    """Handles Google account logout"""

    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    if login_session['provider'] == 'facebook':
        fbdisconnect()
        del login_session['facebook_id']

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON API ENDPOINTS for Categories and Items
@app.route('/categories/<int:category_id>/items/JSON')
def categoryItemsJSON(category_id):
    """Generates JSON endpoint for a Category, listing all its items."""

    try:
        category = session.query(Category).filter_by(id=category_id).one()
        items = session.query(ListItem).filter_by(
            category_id=category_id).all()
        return jsonify(ListItems=[i.serialize for i in items])
    except Exception as e:
        return '''There was a problem with your query %s, please Verify, Redirecting to main page...
            <script> setTimeout(function() {
                  window.location.href = "/";
                 }, 2000);
                 </script> ''' % (str(e))


@app.route('/categories/<int:category_id>/items/<int:item_id>/JSON')
def listItemJSON(category_id, item_id):
    """Generates JSON endpoint for a specific item in a category."""

    try:
        List_Item = session.query(ListItem).filter_by(
            id=item_id, category_id=category_id).one()
        return jsonify(List_Item=List_Item.serialize)
    except Exception as e:
        return '''There was a problem with your query %s, please Verify, Redirecting to main page...
            <script> setTimeout(function() {
                  window.location.href = "/";
                 }, 2000);
                 </script> ''' % (str(e))


@app.route('/categories/JSON')
def categoriesJSON():
    """Generates JSON endpoint with a list of all categories."""

    try:
        categories = session.query(Category).all()
        return jsonify(categories=[r.serialize for r in categories])
    except Exception as e:
        return '''There was a problem with your query %s, please Verify, Redirecting to main page...
            <script> setTimeout(function() {
                  window.location.href = "/";
                 }, 2000);
                 </script> ''' % (str(e))


# Show main page
@app.route('/')
@app.route('/categories/')
def showCategories():
    """Shows main page with a list of all categories."""

    categories = session.query(Category).order_by(asc(Category.name))
    if 'user_id' in login_session:
        return render_template('categories.html', categories=categories,
                               user=getUserInfo(login_session['user_id']))
    else:
        return render_template('pubcategories.html', categories=categories)


# Create new category
@app.route('/categories/new', methods=['GET', 'POST'])
def newCategory():
    """Creates a new category."""

    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if "btn_new" in request.form:
            newCategory = Category(
                name=request.form['name'], user_id=login_session['user_id'])
            session.add(newCategory)
            flash('New Category %s Successfully Created' % newCategory.name)
            session.commit()
            return redirect(url_for('showCategories'))
        else:
            return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html', user=getUserInfo(login_session['user_id']))


# Edit a category
@app.route('/categories/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    """Edits an existing category."""

    if 'username' not in login_session:
        return redirect('/login')

    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if editedCategory.user_id != login_session['user_id']:
        flash('You are not the creator of %s category, and cannot modify it' %
              editedCategory.name)
        return redirect(url_for('showCategories'))
    else:
        if request.method == 'POST':
            if "btn_edit" in request.form:
                if request.form['name']:
                    editedCategory.name = request.form['name']
                    flash('Category Successfully Edited %s' %
                          editedCategory.name)
                    return redirect(url_for('showCategories'))
                else:
                    return redirect(url_for('showCategories'))
            else:
                return redirect(url_for('showCategories'))
        else:
            return render_template('editCategory.html', category=editedCategory, user=getUserInfo(login_session['user_id']))


# Delete a category
@app.route('/categories/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    """Deletes an existing category."""

    if 'username' not in login_session:
        return redirect('/login')

    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    if categoryToDelete.user_id != login_session['user_id']:
        flash('You are not the creator of %s category, and cannot modify it' %
              categoryToDelete.name)
        return redirect(url_for('showCategories'))
    else:
        if request.method == 'POST':
            if "btn_delete" in request.form:
                session.delete(categoryToDelete)
                flash('%s Successfully Deleted' % categoryToDelete.name)
                session.commit()
                return redirect(url_for('showCategories'))
            else:
                return redirect(url_for('showCategories'))
        else:
            return render_template('deleteCategory.html', category=categoryToDelete, user=getUserInfo(login_session['user_id']))


# Show Items page
@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/items')
def showItems(category_id):
    """Shows all items associated to a category."""

    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(ListItem).filter_by(category_id=category_id).all()
    creator = getUserInfo(category.user_id)
    if 'user_id' in login_session:
        if category.user_id != login_session['user_id']:
            return render_template('pubitems.html', items=items, category=category, creator=creator, user=getUserInfo(login_session['user_id']))
        else:
            return render_template('items.html', items=items, category=category, user=getUserInfo(login_session['user_id']))
    else:
        return render_template('pubitems.html', items=items, category=category, creator=creator)


# Create New Item in the Category
@app.route('/categories/<int:category_id>/items/new', methods=['GET', 'POST'])
def newListItem(category_id):
    """Creates an item for a specific category."""

    if 'username' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(id=category_id).one()

    if category.user_id != login_session['user_id']:
        flash('You are not the creator of %s category, and cannot modify it' %
              category.name)
        return redirect(url_for('showItems', category_id=category.id))
    if request.method == 'POST':
        if "btn_new" in request.form:
            newItem = ListItem(name=request.form['name'], description=request.form['description'],
                               category_id=category_id, user_id=login_session['user_id'])
            session.add(newItem)
            session.commit()
            flash('New Catalog Item: %s Successfully Created' % (newItem.name))
            return redirect(url_for('showItems', category_id=category_id))
        else:
            return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('newitem.html', category_id=category_id, user=getUserInfo(login_session['user_id']))


# Edit an Item in the Category
@app.route('/categories/<int:category_id>/items/<int:item_id>/edit', methods=['GET', 'POST'])
def editListItem(category_id, item_id):
    """Edits an existing item in a category."""

    if 'username' not in login_session:
        return redirect('/login')

    editedItem = session.query(ListItem).filter_by(id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()

    if category.user_id != login_session['user_id']:
        flash('You are not the creator of %s category, and cannot modify it' %
              category.name)
        return redirect(url_for('showItems', category_id=category.id))

    if request.method == 'POST':
        if "btn_edit" in request.form:
            if request.form['name']:
                editedItem.name = request.form['name']
            if request.form['description']:
                editedItem.description = request.form['description']
            session.add(editedItem)
            session.commit()
            flash('Catalog Item Successfully Edited')
            return redirect(url_for('showItems', category_id=category_id))
        else:
            return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('edititem.html', item=editedItem, user=getUserInfo(login_session['user_id']))


# Delete an Item in the Category
@app.route('/categories/<int:category_id>/items/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteListItem(category_id, item_id):
    """Deletes an existing item in a category."""

    if 'username' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(id=category_id).one()
    itemToDelete = session.query(ListItem).filter_by(id=item_id).one()

    if category.user_id != login_session['user_id']:
        flash('You are not the creator of %s category, and cannot modify it' %
              category.name)
        return redirect(url_for('showItems', category_id=category.id))

    if request.method == 'POST':
        if "btn_delete" in request.form:
            session.delete(itemToDelete)
            session.commit()
            flash('Catalog Item Successfully Deleted')
            return redirect(url_for('showItems', category_id=category_id))
        else:
            return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('deleteitem.html', item=itemToDelete, user=getUserInfo(login_session['user_id']))


# Show Login page
@app.route('/login')
def showLogin():
    """Shows login page."""

    if 'provider' in login_session:
        print "already logged in"
        flash("You are already logged in, logout first in order to re-login.")
        return redirect(url_for('showCategories'))
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Logout user page
@app.route('/logout')
def disconnect():
    """Handles Logout based on which provider is logged in."""

    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))


# Code to prevent users from entering a page without logging in
# if 'username' not in login_session:
#     return redirect('/login')


# Start web-server using a non-threaded server because otherwise i had
# problems with SQLite
if __name__ == '__main__':
    app.secret_key = 'super_califrastilistico'
    app.debug = True
    app.run(host='0.0.0.0', port=8000, threaded=False)
