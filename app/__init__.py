from flask import Flask
from flask_login import LoginManager
from .config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY

loginManager = LoginManager(app)
loginManager.login_view = 'auth_get'

from . import views
