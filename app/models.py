__author__ = 'xgalv00'

from google.appengine.ext import db


class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class User(db.Model):
    login = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.EmailProperty()