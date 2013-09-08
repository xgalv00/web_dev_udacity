import cgi
from collections import defaultdict
import re
import hmac
import string
import random
import hashlib


import webapp2

from .helper import Handler
from .models import User

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
SECRET = 'udacity'


# Implement the hash_str function to use HMAC and our SECRET instead of md5
def hash_str(s):
    return hmac.new(key=SECRET, msg=s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

# Implement the function valid_pw() that returns True if a user's password
# matches its hash. You will need to modify make_pw_hash.


def make_pw_hash(name, pw, salt=''):
    if salt == '':
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    ###Your code here
    tmp = h.split(',')
    if h == make_pw_hash(name, pw, salt=tmp[1]):
        return True
    else:
        return False


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASS_RE.match(password)
    #return True


def valid_email(email):

    if not email:
        return True

    return EMAIL_RE.match(email)


def clean_input(input_for_clean):
    result = ''
    for char in input_for_clean:
        if char in string.ascii_lowercase:
            result += string.ascii_lowercase[(string.ascii_lowercase.find(char) + 13) % len(string.ascii_lowercase)]
        elif char in string.ascii_uppercase:
            result += string.ascii_uppercase[(string.ascii_uppercase.find(char) + 13) % len(string.ascii_uppercase)]
        else:
            result += char

    return cgi.escape(result, quote=True)

signup_form = 'test'


#def write_signup(self, context, *args, **kwargs):

#    self.response.write(signup_form % context)
def get_username(cookie_val):
    user_id = int(cookie_val.split('|')[0])
    username = str(User.get_by_id(user_id).login)
    return username


class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        cookie_val = self.request.cookies.get('user_id', '')
        if check_secure_val(cookie_val):
            username = get_username(cookie_val)
            self.response.write("<h1>Welcome, {}!</h1>".format(username))
        else:
            self.redirect('/unit4/signup')


class SignupHandler(Handler):
    def get(self):
        d = defaultdict(str)
        self.render('signup.html', **d)

    def post(self):

        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        username_error = ''
        password_error = ''
        verify_error = ''
        email_error = ''
        general_error = ''

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

        context = {'username': username,
                   'password': password,
                   'verify': verify,
                   'email': email,
                   'username_error': username_error,
                   'password_error': password_error,
                   'verify_error': verify_error,
                   'email_error': email_error,
                   'general_error': general_error}

        if not (username_error or password_error or verify_error or email_error):
            q = User.all()
            q.filter("login =", username)

            if q.count() == 0:
                e = User(login=username, password=make_pw_hash(username, password))
                e.put()
                cookie_val = make_secure_val(str(e.key().id()))
                self.response.headers.add_header('Set-Cookie',
                                                 'user_id={}; Path=/'.format(cookie_val))
                self.redirect('/unit4/welcome')
            else:
                context['general_error'] = 'User with this login already exists'
                context['password'] = ''
                context['verify'] = ''
                self.render('signup.html', **context)
        else:
            self.render('signup.html', **context)


def username_exists(username):
    q = User.all()
    q.filter("login =", username)

    if q.count() == 1:
        for result in q.run():
            user_entry = result
            return user_entry


def check_password(user_entry, password):
    user_entry_pw = user_entry.password
    name = user_entry.login
    salt = user_entry_pw.split(',')[1]
    if make_pw_hash(name, password, salt) == user_entry.password:
        return True


class LoginHandler(Handler):
    def get(self):
        d = defaultdict(str)
        self.render('login.html', **d)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        username_error = ''
        password_error = ''
        general_error = ''

        if not valid_username(username):
            username_error = "Username isn't valid"
            password = ''

        if not valid_password(password):
            password_error = "Password isn't valid"
            password = ''

        if not (username_error or password_error):
            user_entry = username_exists(username)
            if user_entry:
                if check_password(user_entry, password):
                    cookie_val = make_secure_val(str(user_entry.key().id()))
                    self.response.headers.add_header('Set-Cookie',
                                                     'user_id={}; Path=/'.format(cookie_val))
                    self.redirect('/unit4/welcome')
                else:
                    general_error = 'Login or password is invalid'
            else:
                general_error = 'Login or password is invalid'

        context = {'username': username,
                   'password': password,
                   'username_error': username_error,
                   'password_error': password_error,
                   'general_error': general_error}

        self.render('login.html', **context)


class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user_id={}; Path=/'.format(''))
        self.redirect('/unit4/signup')