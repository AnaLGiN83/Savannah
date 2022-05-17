import datetime

import peewee
import redis
from .models import User
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


def get_alerts(count, offset=0):  # TODO: Вынести в модель формат вывода данных
    alerts_count = None
    try:
        log_base = redis.StrictRedis(config.REDIS_HOST, config.REDIS_PORT)
        alerts_count = log_base.llen(config.REDIS_ALERTS_NAME)
        if alerts_count == 0:
            return 3, None, 1
        if alerts_count <= offset:
            return 2, None, alerts_count // 50 + 1
        result_count = count
        if alerts_count - offset < count:
            result_count = alerts_count - offset
        data = log_base.lrange(config.REDIS_ALERTS_NAME, offset, offset + result_count - 1)
    except redis.exceptions.ConnectionError as ex:
        return 1, None, (alerts_count or 0) // 50 + 1
    except json.JSONDecodeError:
        return 4, None, (alerts_count or 0) // 50 + 1

    alerts = []
    for line in data:
        event = json.loads(line)
        alerts.append({
            'datetime': event['timestamp'][:-12],
            'interface': event['in_iface'],
            'source_ip': event['src_ip'],
            'source_port': event['src_port'],
            'dest_ip': event['dest_ip'],
            'dest_port': event['dest_port'],
            'protocol': event['proto'],
            'app_protocol': event['app_proto'],
            'sid': event['alert']['signature_id'],
            'signature': event['alert']['signature'],
            'severity': event['alert']['severity'],
        })

    return 0, alerts, alerts_count // 50 + 1


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
