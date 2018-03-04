# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2010-2014 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

import random
import string
import time

from trac.attachment import IAttachmentManipulator
from trac.config import BoolOption, ConfigurationError
from trac.config import IntOption, Option
from trac.core import implements
from trac.env import open_environment
from trac.prefs import IPreferencePanelProvider
from trac.ticket.api import ITicketManipulator
from trac.util import hex_entropy
from trac.util.html import html as tag
from trac.util.presentation import separated
from trac.util.text import exception_to_unicode
from trac.web import auth
from trac.web.chrome import INavigationContributor, add_notice
from trac.web.chrome import add_warning
from trac.web.main import IRequestHandler, IRequestFilter, get_environments
from trac.wiki.api import IWikiPageManipulator

from acct_mgr.api import AccountManager, CommonTemplateProvider
from acct_mgr.api import _, dgettext, ngettext, tag_
from acct_mgr.compat import genshi_template_args
from acct_mgr.db import SessionStore
from acct_mgr.guard import AccountGuard
from acct_mgr.model import last_seen, set_user_attribute
from acct_mgr.notification import NotificationError
from acct_mgr.register import RegistrationModule
from acct_mgr.util import if_enabled, remove_zwsp


class ResetPwStore(SessionStore):
    """User password store for the 'lost password' procedure."""

    def __init__(self):
        super(ResetPwStore, self).__init__()
        self.key = 'password_reset'


class AccountModule(CommonTemplateProvider):
    """Exposes methods for users to do account management on their own.

    Allows users to change their password, reset their password, if they've
    forgotten it, even delete their account.  The settings for the
    AccountManager module must be set in trac.ini in order to use this.
    Password reset procedure depends on both, ResetPwStore and an
    IPasswordHashMethod implementation being enabled as well.
    """

    implements(IAttachmentManipulator, INavigationContributor,
               IPreferencePanelProvider, IRequestFilter, IRequestHandler,
               ITicketManipulator, IWikiPageManipulator)

    _password_chars = string.ascii_letters + string.digits
    password_length = IntOption('account-manager',
        'generated_password_length', 8,
        """Length of the randomly-generated passwords created when resetting
        the password for an account.""")

    reset_password = BoolOption(
        'account-manager', 'reset_password', True,
        "Set to False, if there is no email system setup.")

    def __init__(self):
        self.acctmgr = AccountManager(self.env)
        try:
            self.store = ResetPwStore(self.env)
        except ConfigurationError:
            self.store = None
        self._write_check(log=True)

    def _write_check(self, log=False):
        """Returns all configured write-enabled password stores."""
        writable_stores = \
            self.acctmgr.get_all_supporting_stores('set_password')
        if log:
            if not writable_stores:
                self.log.warning("AccountModule is disabled because no "
                                 "configured password store supports "
                                 "writing.")
            elif self.store not in writable_stores:
                self.log.warning("ResetPwStore is disabled, therefore "
                                 "password reset won't work.")
        return writable_stores

    # INavigationContributor methods

    def get_active_navigation_item(self, req):
        return 'reset_password'

    def get_navigation_items(self, req):
        if self.reset_password_enabled and \
                LoginModule(self.env).enabled and \
                req.authname == 'anonymous':
            yield 'metanav', 'reset_password', \
                  tag.a(_("Forgot your password?"),
                        href=req.href.reset_password())

    def _reset_password_enabled(self, log=False):
        try:
            self.store.hash_method
        except (AttributeError, ConfigurationError):
            return False
        return self.env.is_enabled(self.__class__) and \
               self.reset_password and \
               self._write_check(log) and \
               self.env.is_enabled(self.store.__class__) and \
               self.store.hash_method and True or False

    reset_password_enabled = property(_reset_password_enabled)

    # IPreferencePanelProvider methods

    def get_preference_panels(self, req):
        writable_stores = self._write_check()
        if not writable_stores:
            return
        if req.authname and req.authname != 'anonymous':
            user_store = self.acctmgr.find_user_store(req.authname)
            if user_store in writable_stores:
                yield 'account', _("Account")

    def render_preference_panel(self, req, panel):
        data = dict(_dgettext=dgettext)
        data.update(self._do_account(req))
        return genshi_template_args(self.env, 'prefs_account.html', data)

    # IRequestFilter methods

    def pre_process_request(self, req, handler):
        if not req.authname or req.authname == 'anonymous':
            if req.path_info == '/prefs/account':
                # An anonymous session has no account associated with it, and
                # no account properies too, but general session preferences
                # should always be available.
                req.redirect(req.href.prefs())
            elif req.path_info == '/prefs/advanced' and req.method == 'POST':
                # Prevent setting session ID to one of an authenticated user.
                username = req.args.get('loadsid')
                if username and last_seen(self.env, username):
                    add_warning(req, tag_(
                                "Sorry, but policy prohibits choosing "
                                "'%(username)s' for an anonymous session. "
                                "Login or choose another session ID, please.",
                                username=tag.b(username)))
                    req.redirect(req.href.prefs())
            elif req.method == 'POST' and \
                    req.path_info.split('/')[1] \
                    not in ('attachment', 'newticket', 'ticket', 'wiki'):
                warning = self._check_author(req)
                if warning:
                    add_warning(req, warning[0][1])
                    req.redirect(req.href(req.path_info))
        return handler

    def post_process_request(self, req, template, data, content_type):
        if template is not None and \
                req.authname and req.authname != 'anonymous':
            if req.session.get('force_change_passwd', False):
                # Prevent authenticated usage before another password change.
                redirect_url = req.href.prefs('account')
                if req.href(req.path_info) != redirect_url:
                    req.redirect(redirect_url)
        return template, data, content_type

    # IRequestHandler methods

    def match_request(self, req):
        return req.path_info == '/reset_password' and \
               self._reset_password_enabled(log=True)

    def process_request(self, req):
        data = dict(_dgettext=dgettext)
        if req.authname and req.authname != 'anonymous':
            add_notice(req, tag_(
                "You're already logged in. If you need to change your "
                "password please use the %(prefs_href)s page.",
                prefs_href=tag.a(_("Account Preferences"),
                                 href=req.href.prefs('account'))))
            data['authenticated'] = True
        if req.method == 'POST':
            self._do_reset_password(req)
        return 'reset_password.html', data, None

    # IAttachmentManipulator

    def prepare_attachment(self, req, attachment, fields):
        pass

    def validate_attachment(self, req, attachment):
        return self._check_author(req)

    # ITicketManipulator methods

    def prepare_ticket(self, req, ticket, fields, actions):
        pass

    def validate_ticket(self, req, ticket):
        return self._check_author(req)

    # IWikiPageManipulator methods

    def prepare_wiki_page(self, req, page, fields):
        pass

    def validate_wiki_page(self, req, page):
        return self._check_author(req)

    def _check_author(self, req):
        author = req.args.get('field_reporter') or req.args.get('author')
        if (not req.authname or req.authname == 'anonymous') and author:
            author = remove_zwsp(author)
            if author and last_seen(self.env, author):
                # Prevent impersonating an authenticated user in author field.
                # Use degraded formatting due to T:#6634.
                return [(_("author"), tag_(
                         "Policy prohibits choosing %(username)s for an "
                         "anonymous session because it's a registered "
                         "username. Please login or choose another author "
                         "name.", username=tag.em(author)))]
            return []  # author is not authenticated, but still fine
        return []  # author is authenticated

    def _do_account(self, req):
        assert (req.authname and req.authname != 'anonymous')
        action = req.args.get('action')
        delete_enabled = self.acctmgr.supports('delete_user') and \
                         self.acctmgr.allow_delete_account
        data = {
            'delete_enabled': delete_enabled,
            'delete_msg_confirm':
                _("Are you sure you want to delete your account?"),
        }
        force_change_password = req.session.get('force_change_passwd', False)
        if req.method == 'POST':
            if action == 'save':
                if self._do_change_password(req) and force_change_password:
                    del req.session['force_change_passwd']
                    req.session.save()
                    add_notice(req, _("Thank you for taking the time to "
                                      "update your password."))
                    force_change_password = False
            elif action == 'delete' and delete_enabled:
                self._do_delete(req)
        if force_change_password:
            add_warning(req, tag_(
                "You are required to change password because of a recent "
                "password change request. %(invitation)s",
                invitation=tag.b(_("Please change your password now."))))
        return data

    def _do_change_password(self, req):
        username = req.authname

        old_password = req.args.get('old_password')
        if not self.acctmgr.check_password(username, old_password):
            if old_password:
                add_warning(req, _("Old password is incorrect."))
            else:
                add_warning(req, _("Old password cannot be empty."))
            return
        password = req.args.get('password')
        if not password:
            add_warning(req, _("Password cannot be empty."))
        elif password != req.args.get('password_confirm'):
            add_warning(req, _("The passwords must match."))
        elif password == old_password:
            add_warning(req, _("Password must not match old password."))
        else:
            _set_password(self.env, req, username, password, old_password)
            if req.session.get('password') is not None:
                # Fetch all session_attributes in case new user password is in
                # SessionStore, preventing overwrite by session.save().
                req.session.get_session(req.authname, authenticated=True)
            add_notice(req, _("Password updated successfully."))
            return True

    def _do_delete(self, req):
        username = req.authname

        password = req.args.get('password')
        if not password:
            add_warning(req, _("Password cannot be empty."))
        elif not self.acctmgr.check_password(username, password):
            add_warning(req, _("Password is incorrect."))
        else:
            try:
                self.acctmgr.delete_user(username)
            except NotificationError, e:
                # User wont care for notification, only care for logging here.
                self.log.error(
                    "Unable to send account deletion notification: "
                    "%s", exception_to_unicode(e, traceback=True))
            # Delete the whole session, since records in session_attribute
            # would get restored on logout otherwise.
            req.session.clear()
            req.session.save()
            req.redirect(req.href.login())

    def _do_reset_password(self, req):
        email = req.args.get('email')
        username = req.args.get('username')
        if not username:
            add_warning(req, _("Username is required."))
        elif not email:
            add_warning(req, _("Email is required."))
        else:
            for username_, name, email_ in self.env.get_known_users():
                if username_ == username and email_ == email:
                    self._reset_password(req, username, email)
                    return
            add_warning(req, _(
                "Email and username must match a known account."))

    @property
    def _random_password(self):
        """Create a new random password on admin or user request.

        This method is used by acct_mgr.admin.AccountManagerAdminPanel too.
        """
        return ''.join([random.choice(self._password_chars)
                        for _ in xrange(self.password_length)])

    def _reset_password(self, req, username, email):
        """Store a new, temporary password on admin or user request.

        This method is used by acct_mgr.admin.AccountManagerAdminPanel too.
        """
        acctmgr = self.acctmgr
        new_password = self._random_password
        self.store.set_password(username, new_password)
        try:
            acctmgr._notify('password_reset', username, email, new_password)
        except NotificationError, e:
            msg = _("Error raised while sending a change notification.")
            if req.path_info.startswith('/admin'):
                msg += _("You'll get details with TracLogging enabled.")
            else:
                msg += _("You should report that issue to a Trac admin.")
            add_warning(req, msg)
            self.log.error("Unable to send password reset notification: %s",
                           exception_to_unicode(e, traceback=True))
        except Exception, e:
            add_warning(req, _("Cannot reset password: %(error)s",
                               error=exception_to_unicode(e)))
            self.log.error("Unable to reset password: %s",
                           exception_to_unicode(e, traceback=True))
            return
        else:
            # No message, if method has been called from user admin panel.
            if not req.path_info.startswith('/admin'):
                add_notice(req, _("A new password has been sent to you at "
                                  "<%(email)s>.", email=email))
        if acctmgr.force_passwd_change:
            set_user_attribute(self.env, username, 'force_change_passwd', 1)


class LoginModule(auth.LoginModule, CommonTemplateProvider):
    """Custom login form and processing.

    This is woven with the trac.auth.LoginModule it inherits and overwrites.
    But both can't co-exist, so Trac's built-in authentication module
    must be disabled to use this one.
    """

    # Trac core options, replicated here to not make them disappear by
    # disabling auth.LoginModule.
    check_ip = BoolOption('trac', 'check_auth_ip', 'false',
                          """Whether the IP address of the user should be checked for
                          authentication (''since 0.9'').""")

    ignore_case = BoolOption('trac', 'ignore_auth_case', 'false',
        """Whether login names should be converted to lower case
        (''since 0.9'').""")

    auth_cookie_lifetime = IntOption('trac', 'auth_cookie_lifetime', 0,
         """Lifetime of the authentication cookie, in seconds.

        This value determines how long the browser will cache
        authentication information, and therefore, after how much
        inactivity a user will have to log in again. The default value
        of 0 makes the cookie expire at the end of the browsing
        session. (''since 0.12'')""")

    auth_cookie_path = Option('trac', 'auth_cookie_path', '',
        """Path for the authentication cookie. Set this to the common
        base path of several Trac instances if you want them to share
        the cookie.  (''since 0.12'')""")

    # Options dedicated to acct_mgr.web_ui.LoginModule.
    login_opt_list = BoolOption(
        'account-manager', 'login_opt_list', False,
        """Set to True, to switch login page style showing alternative actions
        in a single listing together.""")

    cookie_refresh_pct = IntOption(
        'account-manager', 'cookie_refresh_pct', 10,
        """Persistent sessions randomly get a new session cookie ID with
        likelihood in percent per work hour given here (zero equals to never)
        to decrease vulnerability of long-lasting sessions.""")

    environ_auth_overwrite = BoolOption(
        'account-manager', 'environ_auth_overwrite', True,
        """Whether environment variable REMOTE_USER should get overwritten
        after processing login form input. Otherwise it will only be set,
        if unset at the time of authentication.""")

    # Update cookies for persistant sessions only 1/day.
    #   hex_entropy returns 32 chars per call equal to 128 bit of entropy,
    #   so it should be technically impossible to explore the hash even within
    #   a year by just throwing forged HTTP requests at the server.
    #   I.e. it would require 1.000.000 machines, each at 5*10^24 requests/s,
    #   equal to a full-scale DDoS attack - an entirely different issue.
    UPDATE_INTERVAL = 86400

    def __init__(self):
        cfg = self.config
        if self.env.is_enabled(self.__class__) and \
                self.env.is_enabled(auth.LoginModule):
            # Disable auth.LoginModule to handle login requests alone.
            self.log.info("Concurrent enabled login modules found, fixing "
                          "configuration ...")
            cfg.set('components', 'trac.web.auth.loginmodule', 'disabled')
            # Changes are intentionally not written to file for persistence.
            # This could cause the environment to reload a bit too early, even
            # interrupting a rewrite in progress by another thread and causing
            # a DoS condition by truncating the configuration file.
            self.log.info("trac.web.auth.LoginModule disabled, giving "
                          "preference to %s.", self.__class__)

        self.cookie_lifetime = self.auth_cookie_lifetime
        if not self.cookie_lifetime > 0:
            # Set the session to expire after some time and not
            #   when the browser is closed - what is Trac core default).
            self.cookie_lifetime = 86400 * 30  # AcctMgr default = 30 days

    def authenticate(self, req):
        if req.method == 'POST' and req.path_info.startswith('/login') and \
                        req.args.get('user_locked') is None:
            username = self._remote_user(req)
            acctmgr = AccountManager(self.env)
            guard = AccountGuard(self.env)
            if guard.login_attempt_max_count > 0:
                if username is None:
                    # Get user for failed authentication attempt.
                    f_user = req.args.get('username')
                    req.args['user_locked'] = False
                    # Log current failed login attempt.
                    guard.failed_count(f_user, req.remote_addr)
                    if guard.user_locked(f_user):
                        # Step up lock time prolongation only while locked.
                        guard.lock_count(f_user, 'up')
                        req.args['user_locked'] = True
                elif guard.user_locked(username):
                    req.args['user_locked'] = True
                    # Void successful login as long as user is locked.
                    username = None
                else:
                    req.args['user_locked'] = False
                    if req.args.get('failed_logins') is None:
                        # Reset failed login attempts counter.
                        req.args['failed_logins'] = \
                            guard.failed_count(username, reset=True)
            else:
                req.args['user_locked'] = False
            if 'REMOTE_USER' not in req.environ or self.environ_auth_overwrite:
                if 'REMOTE_USER' in req.environ:
                    # Complain about another component setting environment
                    # variable for authenticated user.
                    self.log.warning("LoginModule.authenticate: "
                                     "'REMOTE_USER' was set to '%s'",
                                     req.environ['REMOTE_USER'])
                self.log.debug("LoginModule.authenticate: Set 'REMOTE_USER' "
                               "= '%s'", username)
                req.environ['REMOTE_USER'] = username
        return auth.LoginModule.authenticate(self, req)

    authenticate = if_enabled(authenticate)

    match_request = if_enabled(auth.LoginModule.match_request)

    def process_request(self, req):
        if req.path_info.startswith('/login') and req.authname == 'anonymous':
            try:
                referer = self._referer(req)
            except AttributeError:
                # Fallback for Trac 0.11 compatibility.
                referer = req.get_header('Referer')
            # Steer clear of requests going nowhere or loop to self.
            if referer is None or \
                    referer.startswith(req.abs_href('/login')) or \
                    referer.startswith(req.abs_href('/captcha')):
                referer = req.abs_href()
            data = {
                '_dgettext': dgettext,
                'login_opt_list': self.login_opt_list,
                'persistent_sessions':
                    AccountManager(self.env).persistent_sessions,
                'referer': referer,
                'registration_enabled': RegistrationModule(self.env).enabled,
                'reset_password_enabled':
                    AccountModule(self.env).reset_password_enabled
            }
            if req.method == 'POST':
                self.log.debug("LoginModule.process_request: 'user_locked' "
                               "= %s", req.args.get('user_locked'))
                if not req.args.get('user_locked'):
                    # TRANSLATOR: Intentionally obfuscated login error
                    data['login_error'] = _("Invalid username or password")
                else:
                    f_user = req.args.get('username')
                    release_time = AccountGuard(self.env
                                                ).pretty_release_time(req,
                                                                      f_user)
                    if release_time is not None:
                        data['login_error'] = \
                            _("Account locked, please try again after % "
                              "(release_time)s", release_time=release_time)
                    else:
                        data['login_error'] = _("Account locked")
            return 'login.html', data, None
        else:
            n_plural = req.args.get('failed_logins')
            if n_plural > 0:
                add_warning(req, tag(ngettext(
                    "Login after %(attempts)s failed attempt",
                    "Login after %(attempts)s failed attempts",
                    n_plural, attempts=n_plural
                )))
        return auth.LoginModule.process_request(self, req)

    # overrides
    def _get_name_for_cookie(self, req, cookie):
        """Returns the username for the current Trac session.

        It's called by authenticate() when the cookie 'trac_auth' is sent
        by the browser.
        """

        acctmgr = AccountManager(self.env)
        name = None
        # Replicate _get_name_for_cookie() or _cookie_to_name() since Trac 1.0
        # adding special handling of persistent sessions, as the user may have
        # a dynamic IP adress and this would lead to the user being logged out
        # due to an IP address conflict.
        if 'trac_auth_session' in req.incookie or True:
            sql = "SELECT name FROM auth_cookie WHERE cookie=%s AND ipnr=%s"
            args = (cookie.value, req.remote_addr)
            if acctmgr.persistent_sessions or not self.check_ip:
                sql = "SELECT name FROM auth_cookie WHERE cookie=%s"
                args = (cookie.value,)
            name = None
            for name, in self.env.db_query(sql, args):
                break
        if name is None:
            self._expire_cookie(req)

        if acctmgr.persistent_sessions and name and \
                        'trac_auth_session' in req.incookie and \
                        int(req.incookie['trac_auth_session'].value) < \
                                int(time.time()) - self.UPDATE_INTERVAL:
            # Persistent sessions enabled, the user is logged in
            # ('name' exists) and has actually decided to use this feature
            # (indicated by the 'trac_auth_session' cookie existing).
            #
            # NOTE: This method is called on every request.

            # Refresh session cookie
            # Update the timestamp of the session so that it doesn't expire.
            self.log.debug("Updating session %s for user %s", cookie.value,
                           name)
            # Refresh in database
            self.env.db_transaction("""
                UPDATE auth_cookie SET time=%s WHERE cookie=%s
                """, (int(time.time()), cookie.value))

            # Change session ID (cookie.value) now and then as it otherwise
            #   never would change at all (i.e. stay the same indefinitely and
            #   therefore is more vulnerable to be hacked).
            if random.random() + self.cookie_refresh_pct / 100.0 > 1:
                old_cookie = cookie.value
                # Update auth cookie value
                cookie.value = hex_entropy()
                self.log.debug("Changing session id for user %s to %s", name,
                               cookie.value)

                self.env.db_transaction("""
                    UPDATE auth_cookie SET cookie=%s WHERE cookie=%s
                    """, (cookie.value, old_cookie))

                if self.auth_cookie_path:
                    self._distribute_auth(req, cookie.value, name)

            cookie_lifetime = self.cookie_lifetime
            cookie_path = self._get_cookie_path(req)
            req.outcookie['trac_auth'] = cookie.value
            req.outcookie['trac_auth']['path'] = cookie_path
            req.outcookie['trac_auth']['expires'] = cookie_lifetime
            req.outcookie['trac_auth_session'] = int(time.time())
            req.outcookie['trac_auth_session']['path'] = cookie_path
            req.outcookie['trac_auth_session']['expires'] = cookie_lifetime
            if self.env.secure_cookies:
                req.outcookie['trac_auth']['secure'] = True
                req.outcookie['trac_auth_session']['secure'] = True
        return name

    # overrides
    def _do_login(self, req):
        if not req.remote_user:
            if req.method == 'GET':
                # Trac before 0.12 has known weak redirect loop protection.
                # Adding redirect fix from Trac 0.12, and especially avert
                # from 'self._redirect_back', when we see a 'GET' here.
                referer = req.get_header('Referer')
                # Steer clear of requests going nowhere or loop to self
                if referer is None or \
                        referer.startswith(str(req.abs_href()) + '/login'):
                    referer = req.abs_href()
                req.redirect(referer)
            self._redirect_back(req)
        res = auth.LoginModule._do_login(self, req)

        cookie_path = self._get_cookie_path(req)
        # Fix for Trac 0.11, that always sets path to `req.href()`.
        req.outcookie['trac_auth']['path'] = cookie_path
        # Inspect current cookie and try auth data distribution for SSO.
        cookie = req.outcookie.get('trac_auth')
        if cookie and self.auth_cookie_path:
            self._distribute_auth(req, cookie.value, req.remote_user)

        if req.args.get('rememberme', '0') == '1':
            # Check for properties to be set in auth cookie.
            cookie_lifetime = self.cookie_lifetime
            req.outcookie['trac_auth']['expires'] = cookie_lifetime

            # This cookie is used to indicate that the user is actually using
            # the "Remember me" feature. This is necessary for
            # '_get_name_for_cookie()'.
            req.outcookie['trac_auth_session'] = 1
            req.outcookie['trac_auth_session']['path'] = cookie_path
            req.outcookie['trac_auth_session']['expires'] = cookie_lifetime
            if self.env.secure_cookies:
                req.outcookie['trac_auth_session']['secure'] = True
        else:
            # In Trac 0.12 the built-in authentication module may have already
            # set cookie's expires attribute, so because the user did not
            # check 'remember me' we need to delete it here to ensure that the
            # cookie will still expire at the end of the session.
            try:
                del req.outcookie['trac_auth']['expires']
            except KeyError:
                pass
            # If there is a left-over session cookie from a previous
            # authentication session, expire it now.
            if 'trac_auth_session' in req.incookie:
                self._expire_session_cookie(req)
        return res

    def _distribute_auth(self, req, trac_auth, name=None):
        # Single Sign On authentication distribution between multiple
        #   Trac environments managed by AccountManager.
        local_env_name = req.base_path.lstrip('/')

        for env_name, env_path in get_environments(req.environ).iteritems():
            if env_name != local_env_name:
                try:
                    # Cache environment for subsequent invocations.
                    env = open_environment(env_path, use_cache=True)
                    auth_cookie_path = env.config.get('trac',
                                                      'auth_cookie_path')
                    # Consider only Trac environments with equal, non-default
                    # 'auth_cookie_path', which enables cookies to be shared.
                    if auth_cookie_path == self.auth_cookie_path:
                        with env.db_transaction as db:
                            # Authentication cookie values must be unique.
                            # Ensure, there is no other session (or worse:
                            # session ID) associated to it.
                            db("""
                                DELETE FROM auth_cookie WHERE cookie=%s
                                """, (trac_auth,))
                            if not name:
                                env.log.debug("Auth data revoked from: %s",
                                              local_env_name)
                                continue

                            db("""
                                INSERT INTO auth_cookie (cookie,name,ipnr,time)
                                VALUES (%s,%s,%s,%s)
                                """, (trac_auth, name, req.remote_addr,
                                      int(time.time())))

                        env.log.debug("Auth data received from: %s",
                                      local_env_name)
                        self.log.debug("Auth distribution success: %s",
                                       env_name)
                except Exception, e:
                    self.log.debug("Auth distribution skipped for env %s: %s",
                                   env_name,
                                   exception_to_unicode(e, traceback=True))

    def _get_cookie_path(self, req):
        """Determine "path" cookie property from setting or request object."""
        return self.auth_cookie_path or req.base_path or '/'

    # overrides
    def _expire_cookie(self, req):
        """Instruct the user agent to drop the auth_session cookie by setting
        the "expires" property to a date in the past.

        Basically, whenever "trac_auth" cookie gets expired, expire
        "trac_auth_session" too.
        """
        # First of all expire trac_auth_session cookie, if it exists.
        if 'trac_auth_session' in req.incookie:
            self._expire_session_cookie(req)
        # Capture current cookie value.
        cookie = req.incookie.get('trac_auth')
        if cookie:
            trac_auth = cookie.value
        else:
            trac_auth = None
        # Then let auth.LoginModule expire all other cookies.
        auth.LoginModule._expire_cookie(self, req)
        # And finally revoke distributed authentication data too.
        if self.auth_cookie_path and trac_auth:
            self._distribute_auth(req, trac_auth)

    # Keep this code in a separate methode to be able to expire the session
    # cookie trac_auth_session independently of the trac_auth cookie.
    def _expire_session_cookie(self, req):
        """Instruct the user agent to drop the session cookie.

        This is achieved by setting "expires" property to a date in the past.
        """
        cookie_path = self._get_cookie_path(req)
        req.outcookie['trac_auth_session'] = ''
        req.outcookie['trac_auth_session']['path'] = cookie_path
        req.outcookie['trac_auth_session']['expires'] = -10000
        if self.env.secure_cookies:
            req.outcookie['trac_auth_session']['secure'] = True

    def _remote_user(self, req):
        """The real authentication using configured providers and stores."""
        username = req.args.get('username')
        self.log.debug("LoginModule._remote_user: Authentication attempted "
                       "for '%s'", username)
        password = req.args.get('password')
        if not username:
            return None
        acctmgr = AccountManager(self.env)
        acctmod = AccountModule(self.env)
        if acctmod.reset_password_enabled is True:
            reset_store = acctmod.store
        else:
            reset_store = None
        if acctmgr.check_password(username, password) is True:
            if reset_store:
                # Purge any temporary password set for this user before,
                # to avoid DOS by continuously triggered resets from
                # a malicious third party.
                if reset_store.delete_user(username) is True and \
                                'PASSWORD_RESET' not in req.environ:
                    self.env.db_transaction("""
                        DELETE FROM session_attribute
                        WHERE sid=%s
                         AND name='force_change_passwd'
                         AND authenticated=1
                        """, (username,))
            return username
        # Alternative authentication provided by password reset procedure
        elif reset_store:
            if reset_store.check_password(username, password) is True:
                # Lock, required to prevent another authentication
                # (spawned by `set_password()`) from possibly deleting
                # a 'force_change_passwd' db entry for this user.
                req.environ['PASSWORD_RESET'] = username
                # Change password to temporary password from reset procedure
                _set_password(self.env, req, username, password)
                return username
        return None

    def _format_ctxtnav(self, items):
        """Prepare context navigation items for display on login page."""
        return list(separated(items, '|'))

    @property
    def enabled(self):
        # Trac built-in authentication must be disabled to use this one.
        return self.env.is_enabled(self.__class__) and \
               not self.env.is_enabled(auth.LoginModule)


def _set_password(env, req, username, password, old_password=None):
    try:
        AccountManager(env).set_password(username, password,
                                         old_password=old_password)
    except NotificationError, e:
        add_warning(req, _("Error raised while sending a change "
                           "notification.") +
                    _("You should report that issue to a Trac admin."))
        env.log.error('Unable to send password change notification: %s',
                      exception_to_unicode(e, traceback=True))
