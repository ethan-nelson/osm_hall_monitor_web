import flask
import json
from flask_login import login_user, logout_user, current_user, LoginManager, UserMixin
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from xml.etree import ElementTree
import os


app = flask.Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('HALLMONITOR_DB', None)

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

class User(db.Model):
    __tablename__ = 'registered_users'
    id = db.Column(db.BigInteger, primary_key=True, nullable=False)
    username = db.Column(db.Text)
    role = db.Column(db.SmallInteger)

    def __init__(self, id, username):
        self.id = id
        self.username = username

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_admin(self):
        return role

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def __unicode__(self):
        return self.username


@app.route('/api/<kind>')
@app.route('/api/<kind>/<id>')
def api_action(kind, id=None):
    if kind not in ['user', 'object']:
        return 'API kind not allowed; use user or object', 400

    # check user auth here
    if request.method == 'PUT':
        if id is not None:
            return 'Do not specify an id on put', 400
        
    elif request.method == 'PATCH':
        if id is None:
            return '%s ID needed to patch' % (kind,), 400

    elif request.method == 'DELETE':
        if id is None:
            return '%s ID needed to delete' % (kind,), 400

    else:
        return 'Invalid method; only PUT, PATCH, or DELETE.', 405


@app.route('/web/<action>/<kind>')
@app.route('/web/<action>/<kind>/<id>')
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

    elif action == 'edit':
        pass

    elif action == 'delete':
        pass
        

@app.route('/login')
def login():
    redirect_uri = flask.url_for('authorize', _external=True)
    return oauth.osm.authorize_redirect(redirect_uri)


@app.route('/logout')
def logout():
    logout_user()
    return flask.redirect('/')


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
    return flask.redirect('/')


@app.route('/')
@app.route('/web')
def home():
    return flask.render_template('index.html')


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
