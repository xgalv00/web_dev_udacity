__author__ = 'xgalv00'

import string
import cgi
import re
import json
import datetime
import time

import webapp2

from google.appengine.ext import db

from app.models import Blog
from app.helper import Handler


SIMPLE_TYPES = (int, long, float, bool, dict, basestring, list)


def to_dict(model):
    output = {}

    for key, prop in model.properties().iteritems():
        value = getattr(model, key)

        if value is None or isinstance(value, SIMPLE_TYPES):
            output[key] = value
        elif isinstance(value, datetime.date):
            # Convert date/datetime to MILLISECONDS-since-epoch (JS "new Date()").
            ms = time.mktime(value.utctimetuple()) * 1000
            ms += getattr(value, 'microseconds', 0) / 1000
            output[key] = int(ms)
        elif isinstance(value, db.GeoPt):
            output[key] = {'lat': value.lat, 'lon': value.lon}
        elif isinstance(value, db.Model):
            output[key] = to_dict(value)
        else:
            raise ValueError('cannot encode ' + repr(prop))

    return output


class FrontBlogAPIHandler(Handler):
    def get(self):
        blogs = Blog.all()
        blogs.order('-created')
        json_out = json.dumps([to_dict(x) for x in blogs])
        self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
        self.response.write(json_out)
        # self.render('blog.html', blogs=blogs, title='Blog')


class PostAPIHandler(Handler):
    def get(self, post_id):
        json_out = json.dumps(to_dict(Blog.get_by_id(int(post_id))))
        self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
        self.response.write(json_out)


class NewPostHandler(Handler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        subject = cgi.escape(subject, quote=True)
        content = cgi.escape(content, quote=True)

        if subject and content:
            e = Blog(subject=subject, content=content)
            e.put()
            self.redirect('/unit5/blog/{}'.format(e.key().id()))
        else:
            context = {'subject': subject,
                       'content': content,
                       'error': 'some error text'}

            self.render('newpost.html', **context)
