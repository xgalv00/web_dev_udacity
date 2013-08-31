__author__ = 'xgalv00'

from google.appengine.ext import db


class Blog(db.Model):
    title = db.StringProperty(required=True)
    blog_entry = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)