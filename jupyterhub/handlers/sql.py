"""HTTP Handlers for phcpack account management"""

from tornado.escape import url_escape
from tornado import gen
from tornado.httputil import url_concat
from tornado import web

from .base import BaseHandler

# for phcpy db and its support tickets
import pymysql, smtplib # VERIFY: sqlite-3 interface is equivalent
import hashlib, datetime, secrets # NOTE: secrets introduces 3.6+ dep
from email.mime.text import MIMEText

class PHCHandler(BaseHandler): # ValidatingHandler
    """Base class for pages with forms that recycle input, esp. in a validation loop.
       Subclasses may define post(self) in terms of render_ and valid_ methods."""

    @gen.coroutine
    def get(self):
        "Initial page request logic, the trivial default."
        self.finish(self.render_init())

    def phc_db(self):
        """VERIFY: Returns new connection to a database of the following form:
            CREATE TABLE users(Uid, Name_First, Name_Last, Email, Organization, passwd, Created, Ticket, Folder, Tmp);"""

        # TODO: give useful exception when db is unavailable or of wrong form
        cfg = self.config.PHCHandler
        return pymysql.connect(db=cfg.phc_db, host=cfg.phc_db_host)

    @property
    def html(self):
        raise NotImplementedError(
                "PHCHandler subclass must specify a jinja template.")

    # TODO: with fresh_cursor() as c:

    def valid_user(self, login, fname, lname):
        "Does user by this e-mail and name exist?"
        db = self.phc_db(); c = db.cursor()
        c.execute("SELECT Name_First='{}' AND Name_Last='{}' FROM users WHERE Email='{}';"
                    .format(fname, lname, login))

        ret = c.fetchall()
        # print('filter by name: ', ret)
        c.close()
        return len(ret) != 0 and ret[0][0] != 0 and ret[0][0] is not None
            # FIXME: why do trivial results vary?

    def valid_ticket(self, login, ticket):
        "Does user by this e-mail have this ticket active?"
        db = self.phc_db(); c = db.cursor()
        c.execute("SELECT Ticket='{}' FROM users WHERE Email='{}';".format(ticket, login))

        ret = c.fetchall()
        # print('filter by ticket:', ret)
        c.close()
        return len(ret) != 0 and ret[0][0] != 0 and ret[0][0] is not None

    def valid_pass(self, pwd, pwdmatch):
        "Is password nontrivial and matching its verification?"
        return pwd == pwdmatch and pwd is not ""

    def has_folder(self, login):
        "Does user by this e-mail have a folder secret?"
        db = self.phc_db()
        c = db.cursor()
        c.execute("SELECT Folder FROM users WHERE Email='{}';"
                    .format(login))
        s = c.fetchall()
        c.close()
        return len(s) != 0 and s[0][0] is not None and s[0][0] != ""


    def render_init(self):
        "Pass GET and POST arguments to my template."
        return self.render_template(self.html,
            **{k: self.get_argument(k, strip=False) for k in self.request.arguments})

    def render_oops(self, oops,
                    blocked=['password', 'passwordmatch']):
        """Pass GET and POST arguments (especially fields, but not passwords)
            to my template, plus a warning message."""
        return self.render_template(self.html,
                warning = oops,
                **{k: self.get_argument(k, strip=False) for k in self.request.arguments
                                           if k not in blocked})

    def render_ok(self, ok):
        "Pass success message to my template."
        return self.render_template(self.html, success = ok)

    # TODO: this method is more of a mixin
    def phc_email(self, msg):
        """Send a MIMEText e-mail. Fall back to console if server not configured."""
        cfg = self.config.PHCHandler # dict(phcstmp='', phcmail='', phcmailps='')

        # FIXME: document new config keys by subclassing README.
        if 'phcstmp' not in cfg or cfg.phcstmp == '':
            print("Mail server not configured. Sending to console.")
            print(msg) # TEST configuration
            return
        
        server = smtplib.SMTP(cfg.phcstmp)
        server.starttls()  
        server.login(cfg.phcmail, cfg.phcmailps)
        try:
            server.sendmail(cfg.phcmail, [msg['To'], cfg.phcmail], msg.as_string())
        except smtplib.SMTPRecipientsRefused as e:
            # occurs when all recipients were refused
            raise e
        finally:
            server.quit()


class RegisterHandler(PHCHandler):
    """Enters a new user into the database, and sends activation e-mail."""
    @property
    def html(self): return 'register.html'

    @gen.coroutine
    def post(self):
        "Form submission logic."
        data = {k: self.get_argument(k, strip=False) for k in self.request.arguments}
        db = self.phc_db()
        c = db.cursor()

        # TODO: define near other validation queries
        s = c.execute("SELECT Uid FROM users WHERE Email='{}';".format(data['username'])).fetchall()
        c.close()

        if data['username'] == "" or not '@' in data['username']:
            self.finish(self.render_oops('E-mail given is not an address.'))
        elif len(s) != 0:
            self.finish(self.render_oops('E-mail already registered.'))

        elif data['firstname'] == "" or data['lastname'] == "" or data['organization'] == "":
            self.finish(self.render_oops('Please fill out all fields.'))
            # TODO: the organiztion box is a bit short.
        elif not self.valid_pass(data['password'], data['passwordmatch']):
            self.finish(self.render_oops('Passwords don\'t match or weren\'t given.'))

        else:
            ticket = secrets.token_urlsafe(24) # NOTE: was sha(time)
            try:
                self.send_email(data['username'], data['firstname'], ticket)

            except smtplib.SMTPRecipientsRefused as e:
                self.finish(self.render_oops('Could not send mail to that address.'))
            except Exception as e:
                self.finish(self.render_oops(e))

            else:
                # populate new row. do not create folder secret until user activates.
                mungedPass = str(hashlib.sha1(data['password'].encode('utf-8')).hexdigest())
                                # FIXME: salt me
                timestamp = str(datetime.date.today())

                c = db.cursor()
                c.execute("INSERT INTO users VALUES (NULL,'%s','%s','%s','%s','%s','%s','%s','%s',NULL);" % (data['firstname'],data['lastname'],data['username'],data['organization'],mungedPass,timestamp,ticket,""))

                db.commit()
                c.close()
                self.finish(self.render_ok('Please verify your address at '+ data['username']+'.'))

    def send_email(self, email, firstname, ticket):
        msg_cont = """Hello %s,

    Welcome to PHC Web Interface. Please click the following link to activate your account.


    https://%s/hub/activate?login=%s&ticket=%s""" % (firstname,
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
        "Form submission logic."
        data = {k: self.get_argument(k, strip=False) for k in self.request.arguments}

        if not self.valid_user(data['username'], data['firstname'], data['lastname']):
            self.finish(self.render_oops('No user by that name and email found.'))

        elif not self.has_folder(data['username']):
            # don't send resets to unverified emails... lest we clobber the activation ticket.
            self.finish(self.render_oops('Please activate account first.'))
            # FIXME: offer to re-send the e-mail
            
        else:
            ticket = secrets.token_urlsafe(24)
            try:
                self.send_email(data['username'], data['firstname'], ticket)

            except smtplib.SMTPRecipientsRefused as e:
                self.finish(self.render_oops('Could not send recovery email.'))
            except Exception as e:
                self.finish(self.render_oops(e))

            else:
                db = self.phc_db()
                c = db.cursor()
                c.execute("UPDATE users SET Ticket = '{}' WHERE Email = '{}';"
                          .format(ticket, data['username'])) # passwd = NULL
                # NOTE: password invalidation could be used to annoy, and it complicates the logic.
                db.commit()
                c.close()

                self.finish(self.render_ok('Reset done. Recovery e-mail sent to '
                                            +data['username']+'.'))

    def send_email(self, email, firstname, ticket):
        msg_cont = """Hello %s,

    Welcome to PHC Web Interface. Please click the following link to reset your password.


    https://%s/hub/recover?login=%s&ticket=%s""" % (firstname,
        self.config.PHCHandler.host_address, email, ticket)

        msg = MIMEText(msg_cont)
        msg['Subject'] = "Your PHCWEB password has been reset."
        msg['To'] = email
        self.phc_email(msg)


class ActivateHandler(PHCHandler):
    """Declares user folder given a valid ticket. Redirects immediately to login."""

    @gen.coroutine
    def get(self):
        "Form submission logic."
        data = {k: self.get_argument(k, strip=False) for k in self.request.arguments}

        login_url = self.authenticator.login_url(self.hub.base_url)

        if not self.valid_ticket(data['login'], data['ticket']):
            activation = 'Could not activate account with that ticket.'
            data['login'] = '' # do not prefill username
        elif self.has_folder(data['login']):
            activation = 'Account already activated.'
        else:
            # create hard-to-guess UNIX user(name)s. will be prepended with '_'.
            # FIXME: do not delegate user creation to authenticator.
            folder = ''.join([secrets.choice('abcdef0123456789') for i in range(31)])

            db = self.phc_db()
            c = db.cursor()
            c.execute("UPDATE users SET Folder = '{}' WHERE Email = '{}'"
                        .format(folder, data['login']))
            db.commit()
            c.close()
            activation = 'Your account has been activated.'
            
        login_url = url_concat(login_url, {'activation': activation,
                                            'username': data['login']})
        self.redirect(login_url)


class RecoverHandler(PHCHandler):
    """Resets user passwords given a valid ticket."""
    @property
    def html(self): return 'recover.html'

    @gen.coroutine
    def get(self):
        "Block users with invalid recovery ticket."
        login = self.get_argument('login')
        ticket = self.get_argument('ticket')

        if not self.valid_ticket(login, ticket):
            print("Rejected bad recovery ticket " + ticket + " for user " + login + ".")
            self.finish(self.render_template(self.html,
                        error="Invalid ticket, please re-request."))

        elif not self.has_folder(login):
            self.finish(self.render_template(self.html,
                        error="Clever, but please activate your account first."))
        else:
            self.finish(self.render_init())

    @gen.coroutine
    def post(self):
        "Form submission logic."
        data = {k: self.get_argument(k, strip=False)
                for k in self.request.arguments}

        if not self.valid_ticket(data['login'], data['ticket']):
            self.finish(self.render_oops(
                "Ticket got clobbered. Did you already request a new one?"))

        elif not self.valid_pass(data['password'], data['passwordmatch']):
            self.finish(self.render_oops("Passwords given don't match."))

        else:
            # invalidation = secrets.token_urlsafe(24)

            s = hashlib.sha1()
            s.update(data['password'].encode('utf-8'))
            hashed = s.hexdigest()

            db = self.phc_db()
            c = db.cursor()
            c.execute("UPDATE users SET passwd = '{}', Ticket = NULL WHERE Email = '{}';"
                        .format(hashed, data['login'])) # CHANGED from WHERE Ticket

            db.commit()
            c.close()
            self.finish(self.render_ok('Sucessful reset.'))


# /register and /forgot are specific to phcpy's SQL deployment.
# /activate and /recover consume e-mails generated by their respective counterpart.
default_handlers = [
    (r'/register', RegisterHandler),
    (r'/forgot', ForgotPassHandler),

    (r'/activate', ActivateHandler),
    (r'/recover', RecoverHandler),
]
