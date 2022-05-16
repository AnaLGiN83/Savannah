import datetime

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
    error, data = utils.tail_jq(config.EVE_PATH, 10000, "select(.event_type==\"stats\")")
    if error:
        return error, None
    event = json.loads(data[-2])

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


def get_alerts():
    # TODO: Поддержка страничного вывода любого кол-ва тревог
    error, data = utils.tail_jq(config.EVE_PATH, 10000, "select(.event_type==\"alert\")")
    if error:
        return error, None
    data.pop(-1)
    alerts = []
    for line in data:
        event = json.loads(line)
        alerts.append({
            'datetime': event['timestamp'],
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

    return 0, alerts
