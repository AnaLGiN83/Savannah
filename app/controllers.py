import datetime

import peewee
import redis
from .models import User, Alert
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
        log_base = redis.StrictRedis(config.REDIS_HOST, config.REDIS_PORT)
        if log_base.llen(config.REDIS_STATS_NAME) == 0:
            return 2, None
        last_stat = log_base.lindex(config.REDIS_STATS_NAME, 0)
    except redis.exceptions.ConnectionError as ex:
        return 1, None

    try:
        event = json.loads(last_stat)
    except json.JSONDecodeError:
        return 4, None

    return 0, {
        'uptime': str(datetime.timedelta(seconds=event['stats']['uptime'])),
        'packets_captured': event['stats']['capture']['kernel_packets'],
        'capture_errors': event['stats']['capture']['errors'],
        'tcp_packets': event['stats']['decoder']['tcp'],
        'udp_packets': event['stats']['decoder']['udp'],
        'rules_loaded': event['stats']['detect']['engines'][0]['rules_loaded'],
        'rules_failed': event['stats']['detect']['engines'][0]['rules_failed'],
        'alerts': event['stats']['detect']['alert'],
    }


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


def get_savannah_log():
    return 0, "Not exists"


def update_rules():
    return utils.suricata_update()
