import os
import sys
import logging
import logging.handlers
from datetime import datetime

from flask import Flask, current_app
from flask_admin.contrib.mongoengine import ModelView
from flask_cors import CORS, cross_origin

from config import load_config

try:
    reload(sys)
    sys.setdefaultencoding('utf8')
except (AttributeError, NameError):
    pass


# Extensions

from flask_jwt import JWT
from flask.ext.admin import Admin
from flask.ext.login import LoginManager
from flask.ext.mongoengine import MongoEngine

from controllers import all_bp

db = MongoEngine()
login_manager = LoginManager()
admin = Admin()
jwt = JWT()
cors = CORS()

# Models & Users & Roles

class Permission:
    READ = 0x01
    CREATE = 0x02
    UPDATE = 0x04
    DELETE = 0x08
    DEFAULT = READ


class Role(db.Document):
    name = db.StringField()
    permission = db.IntField()

    def __repr__(self):
        return "{}-{}".format(self.name, self.permission)

    def __str__(self):
        return self.__repr__()

    def __unicode__(self):
        return self.__repr__()


class User(db.Document):
    name = db.StringField()
    password = db.StringField()
    email = db.StringField()
    role = db.ReferenceField('Role')

    @property
    def id(self):
        return str(self._id)

    def to_json(self):
        return {"name": self.name,
                "email": self.email 
                }

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class Upload(db.Document):
    filename = db.StringField()
    local_path = db.StringField()
    url = db.StringField()
    done_at = db.DateTimeField(datetime.now)

class Item(db.Document):
    content = db.StringField(required=True)
    created_date = db.DateTimeField()
    completed = db.BooleanField(default=False)
    completed_date = db.DateTimeField()
    created_by = db.ReferenceField('User', required=True)
    notes = db.ListField(db.StringField())
    priority = db.IntField()

    def __repr__(self):
        return "<Item: {} Content: {}>".format(str(self.id),
                                               self.content)

    def to_json(self):
        return {
            'id': str(self.id),
            'content': self.content,
            'completed': self.completed,
            'completed_at': self.completed_date.strftime("%Y-%m-%d %H:%M:%S") if self.completed else "",
            'created_by': self.created_by.name,
            'notes': self.notes,
            'priority': self.priority
        }




def create_app(mode):
    """Create Flask app."""
    config = load_config(mode)

    app = Flask(__name__)
    app.config.from_object(config)

    if not hasattr(app, 'production'):
        app.production = not app.debug and not app.testing

    # Register components
    configure_logging(app)
    register_extensions(app)
    register_blueprint(app)

    return app


def register_extensions(app):
    """Register models."""
    db.init_app(app)
    login_manager.init_app(app)

    # flask-admin configs
    admin.init_app(app)
    admin.add_view(ModelView(User))
    admin.add_view(ModelView(Role))
    cors.init_app(app)

    login_manager.login_view = 'auth.login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.objects(id=user_id).first()

    @app.before_first_request
    def initial_users():
        try:
            user = User(name="kanth",email="kanth@gmail.com",password="kanth")
            user.save()
        except Exception, e:
            print e 
            pass
        
    # jwt config
    def jwt_authenticate(username, password):
        logging.info("username:{}\npassword:{}\n".format(username, password))
        user = User.objects(name=username, password=password).first()
        return user

    def jwt_identity(payload):
        logging.info("payload:{}".format(payload))
        user_id = payload['identity']
        return User.objects(id=user_id).first()

    def make_payload(identity):
        iat = datetime.utcnow()
        exp = iat + current_app.config.get('JWT_EXPIRATION_DELTA')
        nbf = iat + current_app.config.get('JWT_NOT_BEFORE_DELTA')
        identity = str(identity.id)
        return {'exp': exp, 'iat': iat, 'nbf': nbf, 'identity': identity}

    jwt.authentication_handler(jwt_authenticate)
    jwt.identity_handler(jwt_identity)
    jwt.jwt_payload_handler(make_payload)

    jwt.init_app(app)


def register_blueprint(app):
    for bp in all_bp:
        app.register_blueprint(bp)


def configure_logging(app):
    logging.basicConfig()
    if app.config.get('TESTING'):
        app.logger.setLevel(logging.CRITICAL)
        return
    elif app.config.get('DEBUG'):
        app.logger.setLevel(logging.DEBUG)
        return

    app.logger.setLevel(logging.INFO)

    info_log = os.path.join("running-info.log")
    info_file_handler = logging.handlers.RotatingFileHandler(
        info_log, maxBytes=104857600, backupCount=10)
    info_file_handler.setLevel(logging.DEBUG)
    info_file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]')
    )
    app.logger.addHandler(info_file_handler)