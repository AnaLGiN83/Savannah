import datetime

import peewee
import redis
from .models import User, Alert, Stat
from peewee import DoesNotExist
from flask_login import login_user
from . import utils, config
import json


def authenticate(username, password):
    try:
        user = User.get(User.username == username)
        if user.check_password(password):
            return login_user(user)
        return False
    except DoesNotExist:
        return False


def get_daemon_status():
    error, data = utils.ctl_status('suricata')
    if not error:
        return data
    return "Unknown"


def get_last_stats():
    try:
        return 0, Stat.get_by_id(0)
    except redis.exceptions.ConnectionError:
        return 1, None
    except redis.exceptions.RedisError:
        return 2, None
    except json.JSONDecodeError:
        return 3, None
    except peewee.DataError:
        return 4, None


def get_alerts(count, offset=0):
    pages_count = None
    try:
        pages_count = Alert.count() // 50 + 1
        return 0, Alert.get_range(offset, count), pages_count
    except redis.exceptions.ConnectionError:
        return 1, None, pages_count or 1
    except redis.exceptions.RedisError:
        return 2, None, pages_count or 1
    except json.JSONDecodeError:
        return 3, None, pages_count or 1
    except peewee.DataError:
        return 4, None, pages_count or 1


def set_user_admin_by_id(user_id, is_admin):
    try:
        user = User.get(User.id == user_id)
        user.is_admin = is_admin
        if user.save() != 1:
            return 2  # Internal error
    except DoesNotExist:
        return 1
    return 0  # OK


def delete_user_by_id(user_id):
    try:
        user = User.get(User.id == user_id)
        if user.delete_instance() != 1:
            return 2  # Internal error
    except DoesNotExist:
        return 1
    return 0  # OK


def create_user(username, password, is_admin, name=None):
    if isinstance(name, str) and name.strip() == '':
        name = None
    try:
        user = User(username=username, name=name, is_admin=is_admin)
        user.set_password(password)
        if user.save() != 1:
            return 2  # Internal error
    except DoesNotExist:
        return 1
    except peewee.IntegrityError:
        return 3  # User already exists
    return 0  # OK


def get_suricata_log():
    return utils.tail(config.SURICATA_LOG_PATH, 50)


def update_rules():
    return utils.suricata_update()
