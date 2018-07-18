from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   jsonify,
                   url_for,
                   flash,
                   send_from_directory)
import datetime
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import os

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('/var/www/ItemCatalog/ItemCatalog/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"

moderators = ['tzawy2010@gmail.com']
# moderators are the only people who could add , edit or delete a category
# deleting a category will result to delete all its items

# Connect to Database and create database session
engine = create_engine('sqlite:////var/www/ItemCatalog/ItemCatalog/itemcatalog.db',
                       connect_args={'check_same_thread': False}, echo=True)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(string.ascii_uppercase+string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token
    app_id = json.loads(open('/var/www/ItemCatalog/ItemCatalog/fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('/var/www/ItemCatalog/ItemCatalog/fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/oauth/access_token?grant_type'
           '=fb_exchange_token&client_id=%s&client_secret'
           '=%s&fb_exchange_token=%s') % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from
        the server token exchange we have to
        split the token first on commas and select the
        first index which gives us the key : value
        for the server access token then we split it on
        colons to pull out the actual token value
        and replace the remaining quotes with nothing
        so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = ('https://graph.facebook.com/v2.8/me?'
           'access_token=%s&fields=name,id,email') % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = ('https://graph.facebook.com/v2.8/me/picture?'
           'access_token=%s&redirect=0&height=200&width=200') % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    usser = session.query(User).filter_by(id=user_id).one_or_none()
    if usser.picture != login_session['picture']:
        usser.picture = login_session['picture']
        session.add(usser)
        session.commit()
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += """ " style = "width: 300px; height: 300px;border-radius: 150px;
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> """

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = """https://graph.facebook.com/%s/
    permissions?access_token=%s""" % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('/var/www/ItemCatalog/ItemCatalog/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps
                                 ('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'
    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    usser = session.query(User).filter_by(id=user_id).one_or_none()
    if usser.picture != login_session['picture']:
        usser.picture = login_session['picture']
        session.add(usser)
        session.commit()

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += """ " style = "width: 300px; height: 300px;
        border-radius: 150px;-webkit-border-
        radius: 150px;-moz-border-radius: 150px;"> """
    if login_session['email'] in moderators:
        flash("""you are now logged
        in as %s (moderator)""" % login_session['username'])
    else:
        flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one_or_none()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one_or_none()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one_or_none()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        ghf = json.dumps('Failed to revoke token for given user.', 400)
        response = make_response(ghf)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showHome'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showHome'))


# JSON APIs to view Restaurant Information

@app.route('/catalog/JSON')
def categoriesJSON():
    categoriesq = session.query(Category).all()
    categories = [r.serialize for r in categoriesq]
    for x in categoriesq:
        temp = session.query(Item).filter_by(cat_id=x.id).all()
        items = [i.serialize for i in temp]
        if items:
            categories[x.id-1]["Item"] = items
    return jsonify(Category=categories)


# Show all categories
@app.route('/')
def showHome():
    categories = session.query(Category).order_by(asc(Category.name))
    litems = session.query(Item).order_by(Item.date.desc()).limit(5)
    if 'username' not in login_session:
        return render_template('publichome.html',
                               categories=categories, litems=litems)
    else:
        if login_session['email'] in moderators:
            return render_template('home.html', categories=categories,
                                   user=getUserInfo(login_session['user_id']),
                                   litems=litems)
        else:
            return render_template('publichome.html',
                                   categories=categories, user=getUserInfo
                                   (login_session['user_id']), litems=litems)

# Create a new category


@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if login_session['email'] not in moderators:
        flash('you dont have permission')
        return redirect('/')
    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showHome'))
    else:
        return render_template('newCategory.html',
                               user=getUserInfo(login_session['user_id']))

# Edit a category


@app.route('/category/<int:cat_id>/edit/', methods=['GET', 'POST'])
def editCategory(cat_id):
    editedCategory = session.query(
        Category).filter_by(id=cat_id).one_or_none()
    if 'username' not in login_session:
        return redirect('/login')
    if login_session['email'] not in moderators:
        return """<script>function myFunction()
        {alert('You are not authorized to edit this Category.');
            window.location.href = '/';}</script>
            <body onload='myFunction()''>"""
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category Successfully Edited %s' % editedCategory.name)
            return redirect(url_for('showHome'))
    else:
        return render_template('editCategory.html', category=editedCategory,
                               user=getUserInfo(login_session['user_id']))


# Delete a category
@app.route('/category/<int:cat_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(cat_id):
    categoryToDelete = session.query(
        Category).filter_by(id=cat_id).one_or_none()
    if 'username' not in login_session:
        return redirect('/login')
    if login_session['email'] not in moderators:
        return """<script>function myFunction()
        {alert('You are not authorized to delete this category.');
            window.location.href='/';}</script><body onload='myFunction()''>"""
    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('%s Successfully Deleted' % categoryToDelete.name)
        # After delete the category delete its items like on cascade delete
        items = session.query(Item).filter_by(
                                              cat_id=cat_id).all()
        for item in items:
            session.delete(item)

        session.commit()
        return redirect(url_for('showHome', cat_id=cat_id))
    else:
        return render_template('deleteCategory.html',
                               category=categoryToDelete,
                               user=getUserInfo(login_session['user_id']))

# Show a category items


@app.route('/category/<int:cat_id>/')
@app.route('/category/<int:cat_id>/items/')
def showMenu(cat_id):
    category = session.query(Category).filter_by(id=cat_id).one_or_none()
    creator = getUserInfo(category.user_id)
    items = session.query(Item).filter_by(
        cat_id=cat_id).all()
    if 'username' not in login_session:
        return render_template('publiccategory.html', items=items,
                               category=category, creator=creator)
    if login_session['email'] not in moderators:
        return render_template('publiccategory.html',
                               items=items, category=category,
                               creator=creator,
                               user=getUserInfo(login_session['user_id']))
    else:
        return render_template('category.html', items=items, category=category,
                               creator=creator,
                               user=getUserInfo(login_session['user_id']))


# Create a category item
@app.route('/category/<int:cat_id>/items/new/', methods=['GET', 'POST'])
def newItem(cat_id):
    if 'username' not in login_session:
        return """<script>function myFunction()
            {alert('You are not logged in to add item.');
            window.location.href = '/login';}
            </script><body onload='myFunction()''>"""
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(id=cat_id).one_or_none()
    if request.method == 'POST':
        newItem = Item(title=request.form['title'],
                       description=request.form['description'],
                       picture=request.form['picture'],
                       cat_id=cat_id, user_id=login_session['user_id'],
                       date=datetime.datetime.now())
        session.add(newItem)
        session.commit()
        flash('New %s Item Successfully Created' % (newItem.title))
        return redirect(url_for('showItem', item_id=newItem.id))
    else:
        return render_template('newitem.html',
                               cat_id=cat_id,
                               user=getUserInfo(login_session['user_id']),
                               categories=categories)

# Edit a category item


@app.route('/category/<int:cat_id>/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editItem(cat_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Item).filter_by(id=item_id).one_or_none()
    category = session.query(Category).filter_by(id=cat_id).one_or_none()
    categories = session.query(Category).order_by(asc(Category.name))
    if login_session['user_id'] != editedItem.user_id:
        return """<script>function myFunction()
        {alert('You are not authorized to edit this item.');
        window.location.href = '/category/"+str(cat_id)+"';}
        </script><body onload='myFunction()''>"""
    if request.method == 'POST':
        if request.form['title']:
            editedItem.title = request.form['title']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            editedItem.cat_id = request.form['category']
        if request.form['picture']:
            editedItem.picture = request.form['picture']
        editedItem.date = datetime.datetime.now()
        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showItem', item_id=editedItem.id))
    else:
        return render_template('edititem.html', categories=categories,
                               cat_id=cat_id, item_id=item_id,
                               item=editedItem,
                               user=getUserInfo(login_session['user_id']))


# Delete a category item
@app.route('/category/<int:cat_id>/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(cat_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=cat_id).one_or_none()
    itemToDelete = session.query(Item).filter_by(id=item_id).one_or_none()
    if login_session['user_id'] != itemToDelete.user_id:
        return """<script>function myFunction()
            {alert('You are not authorized to delete this item.');
            window.location.href = '
            /category/"+str(cat_id)+"';}
            </script><body onload='myFunction()''>"""
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', cat_id=cat_id))
    else:
        return render_template('deleteItem.html', item=itemToDelete,
                               user=getUserInfo(login_session['user_id']))


# show an item


@app.route('/item/<int:item_id>/')
def showItem(item_id):
    item = session.query(Item).filter_by(id=item_id).one_or_none()
    category = session.query(Category).filter_by(id=item.cat_id).one_or_none()
    if 'username' not in login_session:
        return render_template('publicitem.html',
                               item=item)
    else:
        return render_template('item.html',
                               user=getUserInfo
                               (login_session['user_id']), item=item,
                               category=category)


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico',
                               mimetype='image/vnd.microsoft.icon')

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
