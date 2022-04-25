from peewee import SqliteDatabase, Model, CharField, IntegerField, DateTimeField, datetime as peewee_datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import loginManager
from .config import DB_NAME

db = SqliteDatabase(DB_NAME)


@loginManager.user_loader
def load_user(user_id):
    return User.get(User.id == user_id)


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

    def save(self, *args, **kwargs):
        self.updated_on = peewee_datetime.datetime.now()
        return super(User, self).save(*args, **kwargs)

    def __repr__(self):
        return f"{self.id} : {self.username}"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# If database users table not exists or empty, creating default one
if not db.table_exists('users'):
    User.create_table()
    default_user = User(username='admin')
    default_user.set_password('admin')
    default_user.save()
