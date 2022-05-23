# -*- coding: utf-8 -*-
from flask import Flask
from flask_login import LoginManager
from .config import SECRET_KEY
from flask_babel import Babel

app = Flask(__name__)
app.secret_key = SECRET_KEY

loginManager = LoginManager(app)
loginManager.login_view = 'auth_get'

babel = Babel(app)

LANGUAGES = {
    'en': 'English',
    'ru': 'Русский'
}

from . import views
