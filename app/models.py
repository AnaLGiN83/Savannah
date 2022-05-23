import datetime
import json

import redis
from peewee import SqliteDatabase, Model, CharField, IntegerField, DateTimeField, DoesNotExist, \
    datetime as peewee_datetime, BooleanField
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import loginManager
from .config import DB_NAME, REDIS_HOST, REDIS_PORT, REDIS_ALERTS_NAME, REDIS_STATS_NAME

db = SqliteDatabase(DB_NAME)
redisBase = redis.StrictRedis(REDIS_HOST, REDIS_PORT)


@loginManager.user_loader
def load_user(user_id):
    try:
        return User.get(User.id == user_id)
    except DoesNotExist:
        return None


class User(Model, UserMixin):
    class Meta:
        database = db
        db_table = "users"

    id = IntegerField(primary_key=True)
    name = CharField(null=True)
    username = CharField(50, null=False, unique=True)
    password_hash = CharField(null=False)
    created_on = DateTimeField(default=peewee_datetime.datetime.now())
    updated_on = DateTimeField(default=peewee_datetime.datetime.now())
    is_admin = BooleanField(default=False)

    def save(self, *args, **kwargs):
        self.updated_on = peewee_datetime.datetime.now()
        return super(User, self).save(*args, **kwargs)

    def __repr__(self):
        return f"{self.id} : {self.username}"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Alert(Model):
    database = redisBase
    list_name = REDIS_ALERTS_NAME

    datetime = DateTimeField(null=False)
    interface = CharField(null=False)
    source_ip = CharField(null=False)
    source_port = IntegerField(null=False)
    dest_ip = CharField(null=False)
    dest_port = IntegerField(null=False)
    protocol = CharField(null=False)
    app_protocol = CharField(null=False)
    sid = CharField(null=False)
    signature = CharField(2048, null=False)
    severity = IntegerField(null=False)

    def __eq__(self, other):
        return self.datetime == other.datetime and \
               self.interface == other.interface and \
               self.source_ip == other.source_ip and \
               self.source_port == other.source_port and \
               self.dest_ip == other.dest_ip and \
               self.dest_port == other.dest_port and \
               self.protocol == other.protocol and \
               self.app_protocol == other.app_protocol and \
               self.sid == other.sid and \
               self.signature == other.signature and \
               self.severity == other.severity

    @classmethod
    def parse_from_eve(cls, eve):
        event = json.loads(eve)
        return cls(datetime=event['timestamp'][:-12],
                   interface=event['in_iface'],
                   source_ip=event['src_ip'],
                   source_port=event['src_port'],
                   dest_ip=event['dest_ip'],
                   dest_port=event['dest_port'],
                   protocol=event['proto'],
                   app_protocol=event['app_proto'],
                   sid=event['alert']['signature_id'],
                   signature=event['alert']['signature'],
                   severity=event['alert']['severity']
                   )

    def save(self, force_insert=False, only=None):
        raise PermissionError("Alert model is read-only")

    @classmethod
    def get_by_id(cls, pk):
        return cls.parse_from_eve(
            cls.database.lindex(cls.list_name, pk))

    @classmethod
    def get_range(cls, offset, count):
        alerts_range = []
        redis_range = cls.database.lrange(cls.list_name, offset, offset + count - 1)
        for line in redis_range:
            alerts_range.append(cls.parse_from_eve(line))
        return alerts_range

    @classmethod
    def count(cls):
        return cls.database.llen(cls.list_name)


class Stat(Model):
    database = redisBase
    list_name = REDIS_STATS_NAME

    uptime = DateTimeField(null=False)
    packets_captured = IntegerField(null=False)
    capture_errors = IntegerField(null=False)
    tcp_packets = IntegerField(null=False)
    udp_packets = IntegerField(null=False)
    rules_loaded = IntegerField(null=False)
    rules_failed = IntegerField(null=False)
    alerts = IntegerField(null=False)

    def __eq__(self, other):
        return self.uptime == other.uptime and \
               self.packets_captured == other.packets_captured and \
               self.capture_errors == other.capture_errors and \
               self.tcp_packets == other.tcp_packets and \
               self.udp_packets == other.udp_packets and \
               self.rules_loaded == other.rules_loaded and \
               self.rules_failed == other.rules_failed and \
               self.alerts == other.alerts

    @classmethod
    def parse_from_eve(cls, eve):
        event = json.loads(eve)
        return cls(uptime=str(datetime.timedelta(seconds=event['stats']['uptime'])),
                   packets_captured=event['stats']['capture']['kernel_packets'],
                   capture_errors=event['stats']['capture']['errors'],
                   tcp_packets=event['stats']['decoder']['tcp'],
                   udp_packets=event['stats']['decoder']['udp'],
                   rules_loaded=event['stats']['detect']['engines'][0]['rules_loaded'],
                   rules_failed=event['stats']['detect']['engines'][0]['rules_failed'],
                   alerts=event['stats']['detect']['alert']
                   )

    def save(self, force_insert=False, only=None):
        raise PermissionError("Alert model is read-only")

    @classmethod
    def get_by_id(cls, pk):
        return cls.parse_from_eve(
            cls.database.lindex(cls.list_name, pk))

    @classmethod
    def get_range(cls, offset, count):
        stats_range = []
        redis_range = cls.database.lrange(cls.list_name, offset, offset + count - 1)
        for line in redis_range:
            stats_range.append(cls.parse_from_eve(line))
        return stats_range

    @classmethod
    def count(cls):
        return cls.database.llen(cls.list_name)


# If database users table not exists or empty, creating default one
if not db.table_exists('users'):
    User.create_table()
    default_user = User(username='admin')
    default_user.set_password('admin')
    default_user.is_admin = True
    default_user.save()
