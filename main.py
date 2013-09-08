#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from collections import defaultdict
import string
import cgi
import re

import webapp2


from app.models import Blog
from app import unit4
from app.helper import Handler


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASS_RE.match(password)
    #return True


def valid_email(email):

    if not email:
        return True

    return EMAIL_RE.match(email)


def clean_input(input):
    result = ''
    for char in input:
        if char in string.ascii_lowercase:
            result += string.ascii_lowercase[(string.ascii_lowercase.find(char) + 13) % len(string.ascii_lowercase)]
        elif char in string.ascii_uppercase:
            result += string.ascii_uppercase[(string.ascii_uppercase.find(char) + 13) % len(string.ascii_uppercase)]
        else:
            result += char

    return cgi.escape(result, quote=True)

form = """
    <h1>Rot13</h1>
    <form method="post" action="/unit2/rot13">

        <textarea name='text' style="width:400px;height:200px">%(user_input)s</textarea>
        <br>
        <input type="submit">
    </form>"""

signup_form = """
    <h1>Signup</h1>
    <form method="post" action="/unit2/signup">
        <table>
            <tr>
                <td class="label">
                    Username
                </td>
                <td>
                    <input type="text" name="username" value="%(username)s">
                </td>
                <td class="error">
                %(username_error)s
                </td>
            </tr>

            <tr>
                <td class="label">
                    Password
                </td>
                <td>
                    <input type="password" name="password" value="%(password)s">
                </td>
                <td class="error">
                %(password_error)s
                </td>
            </tr>

            <tr>
                <td class="label">
                    Verify Password
                </td>
                <td>
                    <input type="password" name="verify" value="%(verify)s">
                </td>
                <td class="error">
                %(verify_error)s
                </td>
            </tr>

            <tr>
                <td class="label">
                    Email (optional)
                </td>
                <td>
                    <input type="text" name="email" value="%(email)s">
                </td>
                <td class="error">
                %(email_error)s
                </td>
            </tr>
        </table>

        <input type="submit">
    </form>"""


def write_form(self, user_input=''):
    self.response.write(form % {'user_input': user_input})


class MainHandler(webapp2.RequestHandler):
    def get(self):
        write_form(self)


class Rot13Handler(webapp2.RedirectHandler):
    def get(self):
        write_form(self)

    def post(self):
        user_input = self.request.get('text')
        user_input = clean_input(user_input)
        self.response.write(form % {'user_input': user_input})


def write_signup(self, context, *args, **kwargs):

    self.response.write(signup_form % context)


class SignupHandler(webapp2.RequestHandler):
    def get(self):
        d = defaultdict(str)
        write_signup(self, d)
    
    def post(self):

        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        username_error = ''
        password_error = ''
        verify_error = ''
        email_error = ''

        if not valid_username(username):
            username_error = "Username isn't valid"
            password = ''
            verify = ''

        if not valid_password(password):
            password_error = "Password isn't valid"
            password = ''
            verify = ''

        if password != verify:
            verify_error = "Passwords didn't match"
            password = ''
            verify = ''

        if not valid_email(email):
            email_error = "Provide correct email address"
            password = ''
            verify = ''

        if not (username_error or password_error or verify_error or email_error):
            self.redirect('/unit2/welcome?username={}'.format(username))
        else:
            context = {'username': username,
                       'password': password,
                       'verify': verify,
                       'email': email,
                       'username_error': username_error,
                       'password_error': password_error,
                       'verify_error': verify_error,
                       'email_error': email_error}

            write_signup(self, context)


class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        username = self.request.get('username')
        self.response.write("<h1>Welcome, {}!</h1>".format(username))


class FrontBlogHandler(Handler):
    def get(self):
        blogs = Blog.all()
        blogs.order('-created')
        self.render('blog.html', blogs=blogs, title='Blog')


class NewPostHandler(Handler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        subject = cgi.escape(subject, quote=True)
        content = cgi.escape(content, quote=True)

        if subject and content:
            e = Blog(title=subject, blog_entry=content)
            e.put()
            self.redirect('/unit3/blog/{}'.format(e.key().id()))
        else:
            context = {'subject': subject,
                       'content': content,
                       'error': 'some error text'}

            self.render('newpost.html', **context)


class PostHandler(Handler):
    def get(self, post_id):
        blogs = []
        blogs.append(Blog.get_by_id(int(post_id)))
        self.render('blog.html', blogs=blogs, title='Permalink')


app = webapp2.WSGIApplication([
    (r'/', MainHandler),
    (r'/unit2/rot13', Rot13Handler),
    (r'/unit2/signup', SignupHandler),
    (r'/unit2/welcome', WelcomeHandler),
    (r'/unit3/blog', FrontBlogHandler),
    (r'/unit3/blog/newpost', NewPostHandler),
    (r'/unit3/blog/(\d+)', PostHandler),
    (r'/unit4/signup', unit4.SignupHandler),
    (r'/unit4/login', unit4.LoginHandler),
    (r'/unit4/logout', unit4.LogoutHandler),
    (r'/unit4/welcome', unit4.WelcomeHandler),
], debug=True)


# class TestHandler(webapp2.RequestHandler):
#     def post(self):
#         q = self.request.get("q")
#         self.response.write(q)
#
#         # self.response.headers["Content-Type"] = "text/plain"
#         # self.response.write(self.request)