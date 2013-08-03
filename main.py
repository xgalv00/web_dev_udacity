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
import webapp2
import string
import cgi


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

form = """<form method="post" action="/unit2/rot13">
        <textarea name='text'>%(user_input)s</textarea>
        <br>
        <input type="submit">
    </form>"""


def write_form(self, user_input=''):
    self.response.write(form % {'user_input': user_input})


class MainHandler(webapp2.RequestHandler):
    def get(self):
        write_form(self)


class TestHandler(webapp2.RequestHandler):
    def post(self):
        q = self.request.get("q")
        self.response.write(q)

        # self.response.headers["Content-Type"] = "text/plain"
        # self.response.write(self.request)


class Rot13Handler(webapp2.RedirectHandler):
    def get(self):
        write_form(self)

    def post(self):
        user_input = self.request.get('text')
        user_input = clean_input(user_input)
        self.response.write(form % {'user_input': user_input})


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/unit2/rot13', Rot13Handler)
], debug=True)
