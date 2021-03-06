import flask
import json
import osmhm
from osmhm.models import (
    History,
    History_Objects,
    History_Users,
    Watched_Objects,
    Watched_Users,
)
from flask import request
from flask_login import login_user, logout_user, current_user, LoginManager, UserMixin, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from authlib.integrations.flask_client import OAuth
from xml.etree import ElementTree
from wtforms import (
    SelectField,
    TextField,
)
import os


app = flask.Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('HALLMONITOR_DB', None)
osmhm.config.database_url = os.getenv('HALLMONITOR_DB', None)

oauth = OAuth(app)
oauth.register(
  name='osm',
  client_id=os.getenv('OSM_CONSUMER_KEY', None),
  client_secret=os.getenv('OSM_CONSUMER_SECRET', None),
  request_token_url='https://www.openstreetmap.org/oauth/request_token',
  access_token_url='https://www.openstreetmap.org/oauth/access_token',
  authorize_url='https://www.openstreetmap.org/oauth/authorize',
  api_base_url='https://api.openstreetmap.org/api/0.6/'
)

login_manager = LoginManager()
login_manager.init_app(app)

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    __tablename__ = 'registered_users'
    id = db.Column(db.BigInteger, primary_key=True, nullable=False)
    username = db.Column(db.Text)
    role = db.Column(db.SmallInteger)

    def __init__(self, id, username):
        self.id = id
        self.username = username

    def is_admin(self):
        return role

    def __unicode__(self):
        return self.username

class AddForm(FlaskForm):
    element = TextField('element')
    reason = TextField('reason')
    email = SelectField('email')


def add_watched_user(username, reason, watch_username, watch_userid, email):
    user = Watched_Users(username=username, reason=reason, watch_username=watch_username, watch_userid=watch_userid, email=email)
    db.session.add(user)
    db.session.commit()
    return user.id

def add_watched_object(object, reason, watch_username, watch_userid, email):
    obj = Watched_Objects(object=object, reason=reason, watch_username=watch_username, watch_userid=watch_userid, email=email)
    db.session.add(obj)
    db.session.commit()
    return obj.id

def edit_watched_user(username, reason, watch_userid, email):
    user = db.session.query(Watched_Users).get(id)
    if user and user.authorid == watch_userid:
        user.reason = reason
        user.email = email
        db.session.add(user)
        db.session.commit()
        return user
    else:
        return None

def edit_watched_object(object, reason, watch_userid, email):
    obj = db.session.query(Watched_Objects).get(id)
    if obj and obj.authorid == watch_userid:
        user.reason = reason
        user.email = email
        db.session.add(obj)
        db.session.commit()
        return obj
    else:
        return None

def remove_watched_user(id, watch_userid):
    result = db.session.query(Watched_Users).get(id)
    if result and result.authorid == watch_userid:
        db.session.delete(result)
        db.session.commit()
        return {'ok': True}
    else:
        return None

def remove_watched_object(id, watch_userid):
    result = db.session.query(Watched_Objects).get(id)
    if result and result.authorid == watch_userid:
        db.session.delete(result)
        db.session.commit()
        return {'ok': True}
    else:
        return None

def list_watched_users(watch_userid):
    db.session.query(Watched_Users).filter(Watched_Users.authorid == watch_userid).all()

def list_watched_objects(watch_userid):
    return db.session.query(Watched_Objects).filter(Watched_Objects.authorid == watch_userid).all()

def list_watched_users_events(watch_userid):
    return db.session.query(History_Users).filter(History_Users.wid == watch_userid).all()

def list_watched_objects_events(watch_userid):
    return db.session.query(History_Objects).filter(History_Objects.wid == watch_userid).all()

def remove_watched_user_event(eventid, watch_userid):
    result = db.session.query(History_Users).get(eventid)
    if result and result.authorid == watch_userid:
        db.session.delete(result)
        db.session.commit()
        return {'ok': True}
    else:
        return None

def remove_watched_object_event(eventid, watch_userid):
    result = db.session.query(History_Objects).get(eventid)
    if result and result.authorid == watch_userid:
        db.session.delete(result)
        db.session.commit()
        return {'ok': True}
    else:
        return None

def render_json(data):
    return {'data': data}

def render_error():
    return {'error': True}


def api_action(kind, id=None, request_object=None):
    if kind not in ['user', 'userevent', 'object', 'objectevent']:
        return 'API kind not allowed; use user or object', 400
    if not request_object:
        request_object = request

    # check user auth here
    if request_object.method == 'GET':
        if kind == 'user':
            result = list_watched_users(current_user.id)
        elif kind == 'object':
            result = list_watched_objects(current_user.id)
        elif kind == 'userevent':
            result = list_watched_users_events(current_user.id)
        elif kind == 'objectevent':
            result = list_watched_objects_events(current_user.id)

    elif request_object.method == 'PUT':
        if id is not None:
            return 'Do not specify an id on put', 400
        if kind == 'user':
            result = add_watched_user(request_object.get('element'), request_object.get('reason'), current_user.username, current_user.id, request_object.get('email'))
        elif kind == 'object':
            result = add_watched_object(request_object.get('element'), request_object.get('reason'), current_user.username, current_user.id, request_object.get('email'))
        else:
            return 'API kind not allowed for event', 400

    elif request_object.method == 'PATCH':
        if id is None:
            return '%s ID needed to patch' % (kind,), 400
        if kind == 'user':
            result = edit_watched_user(request_object.get('element'), request_object.get('reason'), current_user.id, request_object.get('email'))
        elif kind == 'object':
            result = edit_watched_object(request_object.get('element'), request_object.get('reason'), current_user.id, request_object.get('email'))
        else:
            return 'API kind not allowed for event', 400

    elif request_object.method == 'DELETE':
        if id is None:
            return '%s ID needed to delete' % (kind,), 400
        if kind == 'user':
            result = remove_watched_user(id, current_user.id)
        elif kind == 'user':
            result = remove_watched_object(id, current_user.id)
        elif kind == 'userevent':
            result = remove_watched_user_event(id, current_user.id)
        elif kind == 'objectevent':
            result = remove_watched_object_event(id, current_user.id)

    else:
        return 'Invalid method; only PUT, PATCH, or DELETE.', 405

    return render_json(result) if result is not None else render_error()


@app.route('/api/<kind>')
@app.route('/api/<kind>/<id>', methods=['GET', 'PUT', 'UPDATE', 'DELETE'])
@login_required
def api(kind, id=None):
    if kind not in ['user', 'object', 'userevent', 'objectevent']:
        return 'View kind not allowed; use user or object', 400

    return api_action(kind, id, request)


@app.route('/html/<action>/<kind>')
@app.route('/html/<action>/<kind>/<id>')
@login_required
def action(action, kind, id=None):
    if action not in ['list', 'add', 'edit', 'delete']:
        return 'Action view not found; use list, add, edit, or delete', 400
    if kind not in ['user', 'object']:
        return 'View kind not allowed; use user or object', 400

    # check user auth here
    if action == 'list':
        if id is not None:
            return 'Do not specify an id on listing', 400

    elif action == 'add':
        if id is not None:
            return 'Do not specify an id on add', 400
        form = AddForm()
        if not form.is_submitted():
            return flask.render_template('add.html', form=form, url_type=kind)

    elif action == 'edit':
        if id is not None:
            return 'You must specify an id on edit', 400

    elif action == 'delete':
        if id is not None:
            return 'You must specify an id on edit', 400

    return api_action(kind, id, request)


@app.route('/html/profile')
@app.route('/profile')
@login_required
def profile():
    if request.method == 'UPDATE':
        update_user(request)
    elif request.method == 'DELETE':
        delete_user(request)
        return flask.redirect('/')

    user_info = load_user(user_id)
    return flask.render_template('user.html', info=user_info)


@app.route('/html/login')
@app.route('/login')
def login():
    redirect_uri = flask.url_for('authorize', _external=True)
    return oauth.osm.authorize_redirect(redirect_uri)


@app.route('/html/logout')
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return flask.redirect('/')


@app.route('/html/authorize')
@app.route('/authorize')
def authorize():
    token = oauth.osm.authorize_access_token()
    response = oauth.osm.get('user/details')
    user = ElementTree.XML(response.text).find('user')
    if 'id' in user.attrib:
        user_id = user.attrib['id']
        user_name = user.attrib['display_name']

        check_user(user_id, user_name)
        login_user(load_user(user_id))
    return flask.redirect('/')


@app.route('/html/privacy')
@app.route('/privacy')
def privacy():
    return flask.render_template('privacy.html')


@app.route('/html')
@app.route('/')
def home():
    return flask.render_template('home.html')


def check_user(user_id, user_name):
    user = load_user(user_id)
    if user:
        if user.username != user_name:
            user.username = user_name
            db.session.add(user)
            db.session.commit()
    else:
        db.session.add(User(id=user_id, name=user_name))
        db.session.commit()        


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)
