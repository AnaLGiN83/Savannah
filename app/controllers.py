from .models import User, load_user
from peewee import DoesNotExist
from flask_login import login_user


def authenticate(username, password):
    try:
        user = User.get(User.username == username)
        if user.check_password(password):
            return login_user(user)
        return False
    except DoesNotExist:
        return False
