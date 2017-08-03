"""HTTP Handlers for the hub server"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

from tornado.escape import url_escape
from tornado import gen
from tornado.httputil import url_concat
from tornado import web

from .base import BaseHandler

# for phcpy db and its support tickets
import sqlite3, smtplib # FIXME: sqlite3 -> pymysql
import secrets # TODO: note 3.6+ dep
import hashlib, datetime # single use
from email.mime.text import MIMEText

class LogoutHandler(BaseHandler):
    """Log a user out by clearing their login cookie."""
    def get(self):
        user = self.get_current_user()
        if user:
            self.log.info("User logged out: %s", user.name)
            self.clear_login_cookie()
            self.statsd.incr('logout')
        if self.authenticator.auto_login:
            self.render('logout.html')
        else:
            self.redirect(self.settings['login_url'], permanent=False)


class LoginHandler(BaseHandler):
    """Render the login page."""

    def _render(self, login_error=None, username=None):
        return self.render_template('login.html',
                next=url_escape(self.get_argument('next', default='')),
                username=username,
                login_error=login_error,
                custom_html=self.authenticator.custom_html,
                login_url=self.settings['login_url'],
                authenticator_login_url=url_concat(
                    self.authenticator.login_url(self.hub.base_url),
                    {'next': self.get_argument('next', '')},
                ),
        )

    @gen.coroutine
    def get(self):
        self.statsd.incr('login.request')
        user = self.get_current_user()
        if user:
            # set new login cookie
            # because single-user cookie may have been cleared or incorrect
            self.set_login_cookie(self.get_current_user())
            self.redirect(self.get_next_url(user), permanent=False)
        else:
            if self.authenticator.auto_login:
                auto_login_url = self.authenticator.login_url(self.hub.base_url)
                if auto_login_url == self.settings['login_url']:
                    # auto_login without a custom login handler
                    # means that auth info is already in the request
                    # (e.g. REMOTE_USER header)
                    user = yield self.login_user()
                    if user is None:
                        # auto_login failed, just 403
                        raise web.HTTPError(403)
                    else:
                        self.redirect(self.get_next_url(user))
                else:
                    if self.get_argument('next', default=False):
                        auto_login_url = url_concat(auto_login_url, {'next': self.get_next_url()})
                    self.redirect(auto_login_url)
                return
            username = self.get_argument('username', default='')
            self.finish(self._render(username=username))

    @gen.coroutine
    def post(self):
        # parse the arguments dict
        data = {}
        for arg in self.request.arguments:
            data[arg] = self.get_argument(arg, strip=False)

        auth_timer = self.statsd.timer('login.authenticate').start()
        user = yield self.login_user(data)
        auth_timer.stop(send=False)

        if user:
            already_running = False
            if user.spawner:
                status = yield user.spawner.poll()
                already_running = (status is None)
            if not already_running and not user.spawner.options_form:
                # logging in triggers spawn
                yield self.spawn_single_user(user)
            self.redirect(self.get_next_url())
        else:
            html = self._render(
                login_error='Invalid username or password',
                username=data['username'],
            )
            self.finish(html)


class PHCHandler(BaseHandler): # ValidatingHandler
    """Base class for pages with forms that recycle input, esp. in a validation loop.
       Subclasses may define post(self) in terms of render_ and valid_ methods."""

    @gen.coroutine
    def get(self):
        self.finish(self.render_init())

    def phc_db(self):
        # print(self.config.keys()) # list of classnames used in config
        # FIXME: ungraceful exception when database of appropriate form unavailable
        return sqlite3.connect(self.config.PHCHandler.phc_db)

    @property
    def html(self):
        raise NotImplementedError(
                "PHCHandler subclass must specify a jinja template.")


    def valid_user(self, login, fname, lname):
        db = self.phc_db()
        c = db.cursor()
        c.execute("SELECT Name_First='{}' AND Name_Last='{}' FROM users WHERE Email='{}';"
                    .format(fname, lname, login))
        ret = c.fetchall()
        print('filter by name: ', ret, len(ret))
        c.close()
        return ret is not None

    def valid_ticket(self, login, ticket):
        db = self.phc_db()
        c = db.cursor()
        c.execute("SELECT Ticket='{}' FROM users WHERE Email='{}';".format(ticket, login))
        ret = c.fetchall()
        print('filter by ticket:', ret, len(ret))
        c.close()
        return ret is not None

    def valid_pass(self, pwd, pwdmatch):
        return pwd == pwdmatch and pwd is not ""

    def has_folder(self, login,):
        db = self.phc_db()
        c = db.cursor()
        c.execute("SELECT Folder FROM users WHERE Email='{}';"
                    .format(login))
        s = c.fetchone()
        c.close()
        return s is not None and s[0] is not None and s[0] is not ""


    def render_init(self):
        return self.render_template(self.html,
            **{k: self.get_argument(k, strip=False) for k in self.request.arguments})

    def render_oops(self, oops,
                    blocked=['password', 'passwordmatch']):
        return self.render_template(self.html,
                warning = oops,
                **{k: self.get_argument(k, strip=False) for k in self.request.arguments
                                           if k not in blocked})

    def render_ok(self, ok):
        return self.render_template(self.html, success = ok)

    # TODO: apply best practices
    def phc_email(self, msg):
        cfg = self.config.PHCHandler # dict(phcstmp='', phcmail='', phcmailps='')

        if cfg.phcstmp == '':
            # raise Exception("Mail server not configured.")
            print(msg) # TEST configuration
            return
        
        server = smtplib.SMTP(cfg.phcstmp)
        server.starttls()  
        server.login(cfg.phcmail, cfg.phcmailps)
        try:
            server.sendmail(cfg.phcmail, [msg['To'], cfg.phcmail], msg.as_string())
        except smtplib.SMTPRecipientsRefused as e:
            raise e
        finally:
            server.quit()


class RegisterHandler(PHCHandler):
    """Sends activation e-mails to new users."""
    @property
    def html(self): return 'register.html'

    @gen.coroutine
    def post(self):
        data = {k: self.get_argument(k, strip=False) for k in self.request.arguments}
        db = self.phc_db()
        c = db.cursor()

        c.execute("SELECT Uid FROM users WHERE Email='{}';".format(data['username']))
        if len(c.fetchall()) == 0:
            ticket = secrets.token_urlsafe(32) # NOTE: changed from sha(time)
   
            try:
                self.send_email(data['username'], data['firstname'], ticket)
            except Exception as e:
                # smtplib.SMTPRecipientsRefused?
                c.close()
                self.finish(self.render_oops('Could not send activation email.'))

            mungedPass = str(hashlib.sha1(data['password'].encode('utf-8')).hexdigest())
                            # FIXME: salt me
            timestamp = str(datetime.date.today())

            # sqlite> CREATE TABLE users(Uid, Name_First, Name_Last, Email, Organization, passwd, Created, Ticket, Folder, Tmp); 
            # FIXME: rows aren't appearing in db. commit fails silently?

            ret = c.execute("INSERT INTO users VALUES (NULL,'%s','%s','%s','%s','%s','%s','%s','%s',NULL);" % (data['firstname'],data['lastname'],data['username'],data['organization'],mungedPass,timestamp,ticket,"")) # create folder on activation
            print(ret)

            try:
                ret = db.commit()
            except e:
                print(e)
            else:
                print(ret)

            c.close()
            self.finish(self.render_ok('Please verify your address at '+
                                    data['username']+'.'))
        else:
            c.close()
            self.finish(self.render_oops('E-mail already registered.'))

    def send_email(self, email, firstname, ticket):
        msg_cont = """Hello %s,

    Welcome to PHC Web Interface. Please click the following link to activate your account.


    %s/hub/activate?login=%s&ticket=%s""" % (firstname,
        self.config.PHCHandler.host_address, email, ticket)

        msg = MIMEText(msg_cont)
        msg['Subject'] = "Welcome %s to PHC Web Interface" % firstname
        msg['To'] = email
        self.phc_email(msg)


class ForgotPassHandler(PHCHandler):
    """Sends password recovery e-mails to existing users."""
    @property
    def html(self): return 'forgot_pass.html'

    @gen.coroutine
    def post(self):
        data = {k: self.get_argument(k, strip=False) for k in self.request.arguments}

        if self.valid_user(data['username'], data['firstname'], data['lastname']):
            # FIXME: check for Folder -> don't send resets to unverified emails (why?)
            ticket = secrets.token_urlsafe(32)

            try:
                self.send_email(data['username'], data['firstname'], ticket)

            except smtplib.SMTPRecipientsRefused as e:
                self.finish(self.render_oops('Could not send recovery email.'))
            except Exception as e:
                self.finish(self.render_oops(e))

            else:
                db = self.phc_db()
                c = db.cursor()
                c.execute("UPDATE users SET Ticket = '{}', passwd = NULL WHERE Email = '{}';"
                          .format(ticket, data['username'])) # TODO: keep old password?
                db.commit()
                c.close()

                self.finish(self.render_ok('Reset done. Recovery e-mail sent to '
                                            +data['username']+'.'))
        else:
            self.finish(self.render_oops('No user by that name and email found.'))

    def send_email(self, email, firstname, ticket):
        msg_cont = """Hello %s,

    Welcome to PHC Web Interface. Please click the following link to reset your password.


    %s/hub/recover?login=%s&ticket=%s""" % (firstname,
        self.config.PHCHandler.host_address, email, ticket)

        msg = MIMEText(msg_cont)
        msg['Subject'] = "Your PHCWEB password has been reset."
        msg['To'] = email
        self.phc_email(msg)


class ActivateHandler(PHCHandler):
    """Declares user folder given a valid ticket."""

    @gen.coroutine
    def get(self):
        data = {k: self.get_argument(k, strip=False) for k in self.request.arguments}

        login_url = self.authenticator.login_url(self.hub.base_url)

        if self.valid_ticket(data['login'], data['ticket']):
            if not self.has_folder(data['login']):
                # TODO: create unique UNIX user(name)s instead
                folder = secrets.token_urlsafe(32)

                db = self.phc_db()
                c = db.cursor() # TODO: reuse cursor
                c.execute("UPDATE users SET Folder = '{}' WHERE Email = '{}'"
                            .format(folder, data['login']))
                db.commit()
                c.close()

                # FIXME: pass login_error to login.html via LoginHandler
                login_error = 'Your account has been activated.'
            else:
                login_error = 'Account already activated.'
                
        else:
            login_error = 'Could not activate account with that ticket.'
            
        login_url = url_concat(login_url, {'login_error': login_error})
        self.redirect(login_url)


class RecoverHandler(PHCHandler):
    """Resets user passwords given a valid ticket."""
    @property
    def html(self): return 'recover.html'

    @gen.coroutine
    def get(self):
        print(self.get_argument('ticket'))
        if self.valid_ticket(self.get_argument('login'), self.get_argument('ticket')):
            self.finish(self.render_init())
        else:
            self.finish(self.render_template(self.html,
                        error="Invalid ticket, please re-request."))

    @gen.coroutine
    def post(self):
        # FIXME: GET arguments do not survive POST (query arguments missing from body)
        # contradicts https://groups.google.com/forum/#!topic/python-tornado/2ciCFlRteOo
        data = {k: self.get_argument(k, strip=False)
                for k in self.request.arguments}
        print(data)
        print(self.path_kwargs) # already scrubbed.

        if self.valid_ticket(data['login'], data['ticket']):
            if self.valid_pass(data['password'], data['passwordmatch']):
                # invalidation = secrets.token_urlsafe(32)

                s = hashlib.sha1()
                s.update(data['password'].encode('utf-8'))
                hashed = s.hexdigest()

                db = self.phc_db()
                c = db.cursor()
                c.execute("UPDATE users SET passwd = '{}', Ticket = NULL WHERE Email = '{}';".format(hashed, data['login'])) # CHANGED from WHERE Ticket

                db.commit()
                c.close()
                self.finish(self.render_ok('Sucessful reset.'))
            else:
                self.finish(self.render_oops("Passwords given don't match."))
        else:
            self.finish(self.render_oops(
                "Ticket got clobbered. Did you already request a new one?"))

            '''
            self.finish(self.render_template('recover.html',
                login=self.get_argument('login', default=''),
                ticket=self.get_argument('ticket', default=''),)
            '''

# /login renders the login page or the "Login with..." link,
# so it should always be registered.
# /logout clears cookies.
# FIXME: fork below
# /register and /forgot are specific to phcpy's SQL deployment.
# /activate and /recover consume e-mails generated by their respective counterpart.
default_handlers = [
    (r"/login", LoginHandler),
    (r"/logout", LogoutHandler),

    (r'/register', RegisterHandler),
    (r'/forgot', ForgotPassHandler),

    (r'/activate', ActivateHandler),
    (r'/recover', RecoverHandler),
]
