# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2010-2011 Steffen Hoffmann <hoff.st@web.de>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

import base64
import random
import re
import string
import time

from datetime import timedelta
from os import urandom
from pkg_resources import resource_filename

from trac import perm, util
from trac.core import Component, TracError, implements
from trac.config import Configuration, IntOption, BoolOption
from trac.prefs import IPreferencePanelProvider
from trac.util.presentation import separated
from trac.util.text import to_unicode
from trac.web import auth
from trac.web.api import IAuthenticator
from trac.web.main import IRequestHandler, IRequestFilter
from trac.web import chrome
from trac.web.chrome import INavigationContributor, ITemplateProvider, \
                            add_script, add_stylesheet
from genshi.core import Markup
from genshi.builder import tag

from acct_mgr.api import AccountManager, _, dgettext, ngettext, tag_, \
                         set_user_attribute
from acct_mgr.db import SessionStore
from acct_mgr.guard import AccountGuard
from acct_mgr.util import containsAny, is_enabled


def _create_user(req, env, check_permissions=True):
    acctmgr = AccountManager(env)
    username = acctmgr.handle_username_casing(
                        req.args.get('username').strip())
    name = req.args.get('name')
    email = req.args.get('email').strip()
    account = {'username' : username,
               'name' : name,
               'email' : email,
              }
    error = TracError('')
    error.account = account

    if not username:
        error.message = _("Username cannot be empty.")
        raise error

    # Prohibit some user names that are important for Trac and therefor
    # reserved, even if they're not in the permission store for some reason.
    if username in ['authenticated', 'anonymous']:
        error.message = _("Username %s is not allowed.") % username
        raise error

    # NOTE: A user may exist in the password store but not in the permission
    #   store. I.e. this happens, when the user (from the password store)
    #   never logged in into Trac. So we have to perform this test here
    #   and cannot just check for the user being in the permission store.
    #   And obfuscate whether an existing user or group name
    #   was responsible for rejection of this user name.
    if acctmgr.has_user(username):
        error.message = _(
            "Another account or group named %s already exists.") % username
        raise error

    # Check whether there is also a user or a group with that name.
    if check_permissions:
        # NOTE: We can't use 'get_user_permissions(username)' here
        #   as this always returns a list - even if the user doesn't exist.
        #   In this case the permissions of "anonymous" are returned.
        #
        #   Also note that we can't simply compare the result of
        #   'get_user_permissions(username)' to some known set of permission,
        #   i.e. "get_user_permissions('authenticated') as this is always
        #   false when 'username' is the name of an existing permission group.
        #
        #   And again obfuscate whether an existing user or group name
        #   was responsible for rejection of this username.
        for (perm_user, perm_action) in \
                perm.PermissionSystem(env).get_all_permissions():
            if perm_user == username:
                error.message = _(
                    "Another account or group named %s already exists.") \
                    % username
                raise error

    # Always exclude some special characters, i.e. 
    #   ':' can't be used in HtPasswdStore
    #   '[' and ']' can't be used in SvnServePasswordStore
    blacklist = acctmgr.username_char_blacklist
    if containsAny(username, blacklist):
        pretty_blacklist = ''
        for c in blacklist:
            if pretty_blacklist == '':
                pretty_blacklist = tag(' \'', tag.b(c), '\'')
            else:
                pretty_blacklist = tag(pretty_blacklist,
                                       ', \'', tag.b(c), '\'')
        error.message = tag(_(
            "The username must not contain any of these characters:"),
            pretty_blacklist)
        raise error

    # Validation of username passed.

    password = req.args.get('password')
    if not password:
        error.message = _("Password cannot be empty.")
        raise error

    if password != req.args.get('password_confirm'):
        error.message = _("The passwords must match.")
        raise error

    # Validation of password passed.

    if if_enabled(EmailVerificationModule) and acctmgr.verify_email:
        if not email:
            error.message = _("You must specify a valid email address.")
            raise error
        elif not re.match('^[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,6}$',
                          email, re.IGNORECASE):
            error.message = _("""The email address specified appears to be
                              invalid. Please specify a valid email address.
                              """)
            raise error
        elif acctmgr.has_email(email):
            error.message = _("""The email address specified is already in
                              use. Please specify a different one.
                              """)
            raise error

    # Validation of email address passed.

    acctmgr.set_password(username, password)

    db = env.get_db_cnx()
    cursor = db.cursor()
    cursor.execute("""
        SELECT  COUNT(*)
        FROM    session
        WHERE   sid=%s
            AND authenticated=1
        """, (username,))
    exists = cursor.fetchone()
    if not exists:
        cursor.execute("""
            INSERT INTO session
                    (sid,authenticated,last_visit)
            VALUES  (%s,1,0)
            """, (username,))

    for attribute in ('name', 'email'):
        value = req.args.get(attribute)
        if not value:
            continue
        set_user_attribute(env, username, attribute, value, db)


class ResetPwStore(SessionStore):
    """User password store for the 'lost password' procedure."""
    def __init__(self):
        self.key = 'password_reset'


class AccountModule(Component):
    """Exposes methods for users to do account management on their own.

    Allows users to change their password, reset their password, if they've
    forgotten it, even delete their account.  The settings for the
    AccountManager module must be set in trac.ini in order to use this.
    """

    implements(IPreferencePanelProvider, IRequestHandler, ITemplateProvider,
               INavigationContributor, IRequestFilter)

    _password_chars = string.ascii_letters + string.digits
    password_length = IntOption(
        'account-manager', 'generated_password_length', 8,
        """Length of the randomly-generated passwords created when resetting
        the password for an account.""")

    reset_password = BoolOption(
        'account-manager', 'reset_password', True,
        'Set to False, if there is no email system setup.')

    def __init__(self):
        self.acctmgr = AccountManager(self.env)
        self.store = ResetPwStore(self.env)
        self._write_check(log=True)

    def _write_check(self, log=False):
        writable = self.acctmgr.get_all_supporting_stores('set_password')
        if not writable and log:
            self.log.warn('AccountModule is disabled because the password '
                          'store does not support writing.')
        return writable

    # IPreferencePanelProvider methods

    def get_preference_panels(self, req):
        writable = self._write_check()
        if not writable:
            return
        if req.authname and req.authname != 'anonymous':
            user_store = self.acctmgr.find_user_store(req.authname)
            if user_store in writable:
                yield 'account', _("Account")

    def render_preference_panel(self, req, panel):
        data = {'account': self._do_account(req),
                '_dgettext': dgettext,
               }
        return 'prefs_account.html', data

    # IRequestHandler methods

    def match_request(self, req):
        return req.path_info == '/reset_password' and \
               self._reset_password_enabled(log=True)

    def process_request(self, req):
        data = {'_dgettext': dgettext,
                'reset': self._do_reset_password(req)
               }
        return 'reset_password.html', data, None

    # IRequestFilter methods

    def pre_process_request(self, req, handler):
        return handler

    def post_process_request(self, req, template, data, content_type):
        if req.authname and req.authname != 'anonymous':
            if req.session.get('force_change_passwd', False):
                redirect_url = req.href.prefs('account')
                if req.href(req.path_info) != redirect_url:
                    req.redirect(redirect_url)
        return (template, data, content_type)

    # INavigationContributor methods

    def get_active_navigation_item(self, req):
        return 'reset_password'

    def get_navigation_items(self, req):
        if not self.reset_password_enabled or LoginModule(self.env).enabled:
            return
        if req.authname == 'anonymous':
            yield 'metanav', 'reset_password', tag.a(
                _("Forgot your password?"), href=req.href.reset_password())

    def _reset_password_enabled(self, log=False):
        return is_enabled(self.env, self.__class__) and \
               self.reset_password and (self._write_check(log) != [])

    reset_password_enabled = property(_reset_password_enabled)

    def _do_account(self, req):
        if not req.authname or req.authname == 'anonymous':
            # DEVEL: Shouldn't this be a more generic URL?
            req.redirect(req.href.wiki())
        action = req.args.get('action')
        delete_enabled = self.acctmgr.supports('delete_user') and \
                             self.acctmgr.allow_delete_account
        data = {'delete_enabled': delete_enabled,
                'delete_msg_confirm': _(
                    "Are you sure you want to delete your account?"),
               }
        force_change_password = req.session.get('force_change_passwd', False)
        if req.method == 'POST':
            if action == 'save':
                data.update(self._do_change_password(req))
                if force_change_password:
                    del(req.session['force_change_passwd'])
                    req.session.save()
                    chrome.add_notice(req, Markup(tag.span(tag_(
                        "Thank you for taking the time to update your password."
                    ))))
                    force_change_password = False
            elif action == 'delete' and delete_enabled:
                data.update(self._do_delete(req))
            else:
                data.update({'error': 'Invalid action'})
        if force_change_password:
            chrome.add_warning(req, Markup(tag.span(_(
                "You are required to change password because of a recent "
                "password change request. "),
                tag.b(_("Please change your password now.")))))
        return data

    def _do_reset_password(self, req):
        if req.authname and req.authname != 'anonymous':
            return {'logged_in': True}
        if req.method != 'POST':
            return {}
        username = req.args.get('username')
        email = req.args.get('email')
        if not username:
            return {'error': _("Username is required")}
        if not email:
            return {'error': _("Email is required")}
        for username_, name, email_ in self.env.get_known_users():
            if username_ == username and email_ == email:
                self._reset_password(username, email)
                break
        else:
            return {'error': _(
                "The email and username must match a known account.")}
        return {'sent_to_email': email}

    def _reset_password(self, username, email):
        acctmgr = self.acctmgr
        new_password = self._random_password()
        try:
            acctmgr._notify('password_reset', username, email, new_password)
        except Exception, e:
            return {'error': ','.join(map(to_unicode, e.args))}
        self.store.set_password(username, new_password)
        if acctmgr.force_passwd_change:
            set_user_attribute(self.env, username, 'force_change_passwd', 1)

    def _random_password(self):
        return ''.join([random.choice(self._password_chars)
                        for _ in xrange(self.password_length)])

    def _do_change_password(self, req):
        user = req.authname

        old_password = req.args.get('old_password')
        if not old_password:
            return {'save_error': _("Old Password cannot be empty.")}
        if not self.acctmgr.check_password(user, old_password):
            return {'save_error': _("Old Password is incorrect.")}

        password = req.args.get('password')
        if not password:
            return {'save_error': _("Password cannot be empty.")}

        if password != req.args.get('password_confirm'):
            return {'save_error': _("The passwords must match.")}

        self.acctmgr.set_password(user, password, old_password)
        if req.session.get('password') is not None:
            # Fetch all session_attributes in case new user password is in
            # SessionStore, to prevent unintended overwrite by session.save().
            req.session.get_session(req.authname, authenticated=True)
        return {'message': _("Password successfully updated.")}

    def _do_delete(self, req):
        user = req.authname

        password = req.args.get('password')
        if not password:
            return {'delete_error': _("Password cannot be empty.")}
        if not self.acctmgr.check_password(user, password):
            return {'delete_error': _("Password is incorrect.")}

        self.acctmgr.delete_user(user)
        # Delete the whole session since records in session_attribute would
        # get restored on logout otherwise.
        req.session.clear()
        req.session.save()
        req.redirect(req.href.logout())

    # ITemplateProvider methods

    def get_htdocs_dirs(self):
        """Return the absolute path of a directory containing additional
        static resources (such as images, style sheets, etc).
        """
        return []

    def get_templates_dirs(self):
        """Return the absolute path of the directory containing the provided
        Genshi templates.
        """
        return [resource_filename(__name__, 'templates')]


class RegistrationModule(Component):
    """Provides users the ability to register a new account.

    Requires configuration of the AccountManager module in trac.ini.
    """

    implements(INavigationContributor, IRequestHandler, ITemplateProvider)

    def __init__(self):
        self.acctmgr = AccountManager(self.env)
        self._enable_check(log=True)

    def _enable_check(self, log=False):
        env = self.env
        writable = self.acctmgr.supports('set_password')
        ignore_case = auth.LoginModule(env).ignore_case
        if log:
            if not writable:
                self.log.warn('RegistrationModule is disabled because the '
                              'password store does not support writing.')
            if ignore_case:
                self.log.debug('RegistrationModule will allow lowercase '
                               'usernames only and convert them forcefully '
                               'as required, while \'ignore_auth_case\' is '
                               'enabled in [trac] section of your trac.ini.')
        return is_enabled(env, self.__class__) and writable

    enabled = property(_enable_check)

    # INavigationContributor methods

    def get_active_navigation_item(self, req):
        return 'register'

    def get_navigation_items(self, req):
        loginmod = LoginModule(self.env)
        if not self.enabled:
            return
        if req.authname == 'anonymous':
            yield 'metanav', 'register', tag.a(_("Register"),
                                               href=req.href.register())

    # IRequestHandler methods

    def match_request(self, req):
        return req.path_info == '/register' and self._enable_check(log=True)

    def process_request(self, req):
        if req.authname != 'anonymous':
            req.redirect(req.href.prefs('account'))
        action = req.args.get('action')
        data = {'acctmgr' : { 'username' : None,
                              'name' : None,
                              'email' : None,
                            },
                '_dgettext': dgettext,
               }
        data['verify_account_enabled'] = is_enabled(self.env,
                                                    EmailVerificationModule)
        if req.method == 'POST' and action == 'create':
            try:
                _create_user(req, self.env)
            except TracError, e:
                data['registration_error'] = e.message
                data['acctmgr'] = getattr(e, 'acctmgr', '')
            else:
                chrome.add_notice(req, Markup(tag.span(tag(_(
                     """Registration has been finished successfully.
                     You may login as user %(user)s now.""",
                     user=tag.b(req.args.get('username')))))))
                req.redirect(req.href.login())
        data['reset_password_enabled'] = AccountModule(self.env
                                                      ).reset_password_enabled
        return 'register.html', data, None

    # ITemplateProvider

    def get_htdocs_dirs(self):
        """Return the absolute path of a directory containing additional
        static resources (such as images, style sheets, etc).
        """
        return []

    def get_templates_dirs(self):
        """Return the absolute path of the directory containing the provided
        Genshi templates.
        """
        return [resource_filename(__name__, 'templates')]


def if_enabled(func):
    def wrap(self, *args, **kwds):
        if not self.enabled:
            return None
        return func(self, *args, **kwds)
    return wrap


class LoginModule(auth.LoginModule):
    """Custom login form and processing.

    This is woven with the trac.auth.LoginModule it inherits and overwrites.
    But both can't co-exist, so Trac's built-in authentication module
    must be disabled to use this one.
    """

    implements(ITemplateProvider)

    login_opt_list = BoolOption(
        'account-manager', 'login_opt_list', False,
        """Set to True, to switch login page style showing alternative actions
        in a single listing together.""")

    def authenticate(self, req):
        if req.method == 'POST' and req.path_info.startswith('/login'):
            user = self._remote_user(req)
            acctmgr = AccountManager(self.env)
            guard = AccountGuard(self.env)
            if guard.login_attempt_max_count > 0:
                if user is None:
                    if req.args.get('user_locked') is None:
                        # get user for failed authentication attempt
                        f_user = req.args.get('user')
                        req.args['user_locked'] = False
                        if acctmgr.user_known(f_user) is True:
                            if guard.user_locked(f_user) is False:
                                # log current failed login attempt
                                guard.failed_count(f_user, req.remote_addr)
                                if guard.user_locked(f_user) is True:
                                    # step up lock time prolongation
                                    # only when just triggering the lock
                                    guard.lock_count(f_user, 'up')
                                    req.args['user_locked'] = True
                            else:
                                # enforce lock
                                req.args['user_locked'] = True
                else:
                    if guard.user_locked(user) is not False:
                        req.args['user_locked'] = True
                        # void successful login as long as user is locked
                        user = None
                    else:
                        req.args['user_locked'] = False
                        if req.args.get('failed_logins') is None:
                            # Reset failed login attempts counter
                            req.args['failed_logins'] = guard.failed_count(
                                                         user, reset = True)
            if 'REMOTE_USER' not in req.environ:
                req.environ['REMOTE_USER'] = user
        return auth.LoginModule.authenticate(self, req)

    authenticate = if_enabled(authenticate)

    match_request = if_enabled(auth.LoginModule.match_request)

    def process_request(self, req):
        env = self.env
        if req.path_info.startswith('/login') and req.authname == 'anonymous':
            guard = AccountGuard(env)
            try:
                referer = self._referer(req)
            except AttributeError:
                # Fallback for Trac 0.11 compatibility.
                referer = req.get_header('Referer')
            # Steer clear of requests going nowhere or loop to self
            if referer is None or \
                    referer.startswith(str(req.abs_href()) + '/login'):
                referer = req.abs_href()
            data = {
                '_dgettext': dgettext,
                'login_opt_list': self.login_opt_list == True,
                'persistent_sessions': AccountManager(env
                                       ).persistent_sessions,
                'referer': referer,
                'registration_enabled': RegistrationModule(env).enabled,
                'reset_password_enabled': AccountModule(env
                                          ).reset_password_enabled
            }
            if req.method == 'POST':
                self.log.debug('user_locked: ' + \
                               str(req.args.get('user_locked', False)))
                if not req.args.get('user_locked') is True:
                    # TRANSLATOR: Intentionally obfuscated login error
                    data['login_error'] = _("Invalid username or password")
                else:
                    f_user = req.args.get('user')
                    release_time = guard.pretty_release_time(req, f_user)
                    if not release_time is None:
                        data['login_error'] = _(
                            """Account locked, please try again after
                            %(release_time)s
                            """, release_time=release_time)
                    else:
                        data['login_error'] = _("Account locked")
            return 'login.html', data, None
        else:
            n_plural=req.args.get('failed_logins')
            if n_plural > 0:
                chrome.add_warning(req, Markup(tag.span(tag(ngettext(
                    "Login after %(attempts)s failed attempt",
                    "Login after %(attempts)s failed attempts",
                    n_plural, attempts=n_plural
                )))))
        return auth.LoginModule.process_request(self, req)

    # overrides
    def _get_name_for_cookie(self, req, cookie):
        """Returns the user name for the current Trac session.

        It's called by authenticate() when the cookie 'trac_auth' is sent
        by the browser.
        """

        acctmgr = AccountManager(self.env)

        # Disable IP checking when a persistent session is available, as the
        # user may have a dynamic IP adress and this would lead to the user 
        # being logged out due to an IP address conflict.
        checkIPSetting = self.check_ip and acctmgr.persistent_sessions and \
                         'trac_auth_session' in req.incookie
        if checkIPSetting:
            self.env.config.set('trac', 'check_auth_ip', False)
        
        name = auth.LoginModule._get_name_for_cookie(self, req, cookie)
        
        if checkIPSetting:
            # Re-enable IP checking
            self.env.config.set('trac', 'check_auth_ip', True)
        
        if acctmgr.persistent_sessions and name and \
                'trac_auth_session' in req.incookie:
            # Persistent sessions enabled, the user is logged in
            # ('name' exists) and has actually decided to use this feature
            # (indicated by the 'trac_auth_session' cookie existing).
            # 
            # NOTE: This method is called on every request.
            
            # Update the timestamp of the session so that it doesn't expire
            self.env.log.debug('Updating session %s for user %s' %
                                (cookie.value, name))
                                
            # Refresh in database
            db = self.env.get_db_cnx()
            cursor = db.cursor()
            cursor.execute("""
                UPDATE  auth_cookie
                    SET time=%s
                WHERE   cookie=%s
                """, (int(time.time()), cookie.value))
            db.commit()
            
            # Refresh session cookie
            # TODO Change session id (cookie.value) now and then as it
            #   otherwise never would change at all (i.e. stay the same
            #   indefinitely and therefore is vulnerable to be hacked).
            req.outcookie['trac_auth'] = cookie.value

            # check for properties to be set in auth cookies,
            # defined since Trac 0.12
            try:
                cookie_path = self.auth_cookie_path or req.base_path or '/'
            except AttributeError:
                # Fallback for Trac 0.11 compatibility
                cookie_path = req.base_path or '/'
            req.outcookie['trac_auth'] = cookie.value
            req.outcookie['trac_auth']['path'] = cookie_path

            t = 86400 * 30 # AcctMgr default - Trac core defaults to 0 instead
            cookie_lifetime = self.env.config.getint(
                                         'trac', 'auth_cookie_lifetime', t)
            if cookie_lifetime > 0:
                req.outcookie['trac_auth']['expires'] = cookie_lifetime
            if self.env.secure_cookies:
                req.outcookie['trac_auth']['secure'] = True

            req.outcookie['trac_auth_session'] = 1
            req.outcookie['trac_auth_session']['path'] = cookie_path
            if cookie_lifetime > 0:
                req.outcookie['trac_auth_session']['expires'] = cookie_lifetime
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
        if req.args.get('rememberme', '0') == '1':
            # check for properties to be set in auth cookies,
            # defined since Trac 0.12
            try:
                cookie_path = self.auth_cookie_path or req.base_path or '/'
            except AttributeError:
                # Fallback for Trac 0.11 compatibility
                cookie_path = req.base_path or '/'
            t = 86400 * 30 # AcctMgr default - Trac core defaults to 0 instead
            cookie_lifetime = self.env.config.getint(
                                         'trac', 'auth_cookie_lifetime', t)
            # Set the session to expire after some time
            # (and not when the browser is closed - what is the default).
            if cookie_lifetime > 0:
                req.outcookie['trac_auth']['expires'] = cookie_lifetime
            
            # This cookie is used to indicate that the user is actually using
            # the "Remember me" feature. This is necessary for 
            # '_get_name_for_cookie()'.
            req.outcookie['trac_auth_session'] = 1
            req.outcookie['trac_auth_session']['path'] = cookie_path
            if cookie_lifetime > 0:
                req.outcookie['trac_auth_session']['expires'] = cookie_lifetime
        return res

    # overrides
    def _do_logout(self, req):
        auth.LoginModule._do_logout(self, req)
        
        # Expire the persistent session cookie
        try:
            cookie_path = self.auth_cookie_path or req.base_path or '/'
        except AttributeError:
            # Fallback for Trac 0.11 compatibility
            cookie_path = req.base_path or '/'
        req.outcookie['trac_auth_session'] = ''
        req.outcookie['trac_auth_session']['path'] = cookie_path
        req.outcookie['trac_auth_session']['expires'] = -10000

    def _remote_user(self, req):
        """The real authentication using configured providers and stores."""
        user = req.args.get('user')
        password = req.args.get('password')
        if not user or not password:
            return None
        acctmgr = AccountManager(self.env)
        acctmod = AccountModule(self.env)
        if acctmod.reset_password_enabled == True:
            reset_store = acctmod.store
        else:
            reset_store = None
        if acctmgr.check_password(user, password) == True:
            if reset_store:
                # Purge any temporary password set for this user before,
                # to avoid DOS by continuously triggered resets from
                # a malicious third party.
                if reset_store.delete_user(user) == True and \
                        'PASSWORD_RESET' not in req.environ:
                    db = self.env.get_db_cnx()
                    cursor = db.cursor()
                    cursor.execute("""
                        DELETE
                        FROM    session_attribute
                        WHERE   sid=%s
                            AND name='force_change_passwd'
                            AND authenticated=1
                        """, (user,))
                    db.commit()
            return user
        # Alternative authentication provided by password reset procedure
        elif reset_store:
            if reset_store.check_password(user, password) == True:
                # Lock, required to prevent another authentication
                # (spawned by `set_password()`) from possibly deleting
                # a 'force_change_passwd' db entry for this user.
                req.environ['PASSWORD_RESET'] = user
                # Change password to temporary password from reset procedure
                acctmgr.set_password(user, password)
                return user
        return None

    def _format_ctxtnav(self, items):
        """Prepare context navigation items for display on login page."""
        return list(separated(items, '|'))

    def enabled(self):
        # Admin must disable the built-in authentication to use this one.
        return not is_enabled(self.env, auth.LoginModule)

    enabled = property(enabled)

    # ITemplateProvider methods

    def get_htdocs_dirs(self):
        """Return the absolute path of a directory containing additional
        static resources (such as images, style sheets, etc).
        """
        return []

    def get_templates_dirs(self):
        """Return the absolute path of the directory containing the provided
        Genshi templates.
        """
        return [resource_filename(__name__, 'templates')]


class EmailVerificationModule(Component):
    """Performs email verification on every new or changed address.

    A working email sender for Trac (!TracNotification or !TracAnnouncer)
    is strictly required to enable this module's functionality.

    Anonymous users should register and perms should be tweaked, so that
    anonymous users can't edit wiki pages and change or create tickets.
    So this email verification code won't be used on them. 
    """

    implements(IRequestFilter, IRequestHandler, ITemplateProvider)

    def __init__(self, *args, **kwargs):
        self.email_enabled = True
        if self.config.getbool('announcer', 'email_enabled') != True and \
                self.config.getbool('notification', 'smtp_enabled') != True:
            self.email_enabled = False
            if is_enabled(self.env, self.__class__) == True:
                self.env.log.warn(self.__class__.__name__ + \
                    ' can\'t work because of missing email setup.')

    # IRequestFilter methods

    def pre_process_request(self, req, handler):
        if not req.session.authenticated:
            # Permissions for anonymous users remain unchanged.
            return handler
        if AccountManager(self.env).verify_email and handler is not self and \
                'email_verification_token' in req.session and \
                not req.perm.has_permission('ACCTMGR_ADMIN'):
            # TRANSLATOR: Your permissions have been limited until you ...
            link = tag.a(_("verify your email address"),
                         href=req.href.verify_email())
            # TRANSLATOR: ... verify your email address
            chrome.add_warning(req, Markup(tag.span(tag_(
                "Your permissions have been limited until you %(link)s.",
                link=link))))
            req.perm = perm.PermissionCache(self.env, 'anonymous')
        return handler

    def post_process_request(self, req, template, data, content_type):
        if not req.session.authenticated:
            # Don't start the email verification precedure on anonymous users.
            return template, data, content_type

        email = req.session.get('email')
        # Only send verification if the user entered an email address.
        acctmgr = AccountManager(self.env)
        if acctmgr.verify_email and self.email_enabled is True and email and \
                email != req.session.get('email_verification_sent_to') and \
                not req.perm.has_permission('ACCTMGR_ADMIN'):
            req.session['email_verification_token'] = self._gen_token()
            req.session['email_verification_sent_to'] = email
            acctmgr._notify(
                'email_verification_requested', 
                req.authname, 
                req.session['email_verification_token']
            )
            # TRANSLATOR: An email has been sent to %(email)s
            # with a token to ... (the link label for following message)
            link = tag.a(_("verify your new email address"),
                         href=req.href.verify_email())
            # TRANSLATOR: ... verify your new email address
            chrome.add_notice(req, Markup(tag.span(tag_(
                """An email has been sent to %(email)s with a token to
                %(link)s.""",
                email=email, link=link))))
        return template, data, content_type

    # IRequestHandler methods

    def match_request(self, req):
        return req.path_info == '/verify_email'

    def process_request(self, req):
        if not req.session.authenticated:
            chrome.add_warning(req, Markup(tag.span(tag_(
                "Please log in to finish email verification procedure."))))
            req.redirect(req.href.login())
        if 'email_verification_token' not in req.session:
            chrome.add_notice(req, _("Your email is already verified."))
        elif req.method == 'POST' and 'resend' in req.args:
            AccountManager(self.env)._notify(
                'email_verification_requested', 
                req.authname, 
                req.session['email_verification_token']
            )
            chrome.add_notice(req,
                    _("A notification email has been resent to <%s>."),
                    req.session.get('email'))
        elif 'verify' in req.args:
            # allow via POST or GET (the latter for email links)
            if req.args['token'] == req.session['email_verification_token']:
                del req.session['email_verification_token']
                chrome.add_notice(
                    req, _("Thank you for verifying your email address."))
                req.redirect(req.href.prefs())
            else:
                chrome.add_warning(req, _("Invalid verification token"))
        data = {'_dgettext': dgettext}
        if 'token' in req.args:
            data['token'] = req.args['token']
        if 'email_verification_token' not in req.session:
            data['button_state'] = { 'disabled': 'disabled' }
        return 'verify_email.html', data, None

    def _gen_token(self):
        return base64.urlsafe_b64encode(urandom(6))

    # ITemplateProvider methods

    def get_htdocs_dirs(self):
        """Return the absolute path of a directory containing additional
        static resources (such as images, style sheets, etc).
        """
        return []

    def get_templates_dirs(self):
        """Return the absolute path of the directory containing the provided
        Genshi templates.
        """
        return [resource_filename(__name__, 'templates')]

