# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2010-2013 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

import inspect
import re

from genshi.builder import tag
from genshi.core import Markup

from trac.admin import IAdminPanelProvider
from trac.core import Component, TracError, implements
from trac.config import BoolOption, Option
from trac.perm import PermissionCache, PermissionSystem
from trac.util.datefmt import format_datetime, to_datetime
from trac.util.presentation import Paginator
from trac.web.api import IAuthenticator
from trac.web.chrome import Chrome, add_ctxtnav, add_link, add_notice
from trac.web.chrome import add_script, add_stylesheet, add_warning
from trac.wiki.formatter import format_to_html

from acct_mgr.api import AccountManager, CommonTemplateProvider
from acct_mgr.api import _, N_, dgettext, gettext, ngettext, tag_
from acct_mgr.guard import AccountGuard
from acct_mgr.model import del_user_attribute, email_verified
from acct_mgr.model import get_user_attribute, last_seen
from acct_mgr.model import set_user_attribute
from acct_mgr.register import EmailVerificationModule, RegistrationError
from acct_mgr.register import RegistrationModule
from acct_mgr.web_ui import AccountModule, LoginModule
from acct_mgr.util import as_int, is_enabled, exception_to_unicode
from acct_mgr.util import get_pretty_dateinfo, pretty_precise_timedelta


def fetch_user_data(env, req, filters=None):
    acctmgr = AccountManager(env)
    guard = AccountGuard(env)
    accounts = {}
    for username in acctmgr.get_users():
        if req.perm.has_permission('ACCTMGR_USER_ADMIN'):
            url = req.href.admin('accounts', 'users', user=username)
        else:
            url = None
        accounts[username] = {'username': username, 'review_url': url}
        if guard.user_locked(username):
            accounts[username]['locked'] = True
            t_lock = guard.lock_time(username)
            if t_lock > 0:
                t_release = guard.pretty_release_time(req, username)
                accounts[username]['release_hint'] = _(
                        "Locked until %(t_release)s",
                        t_release=t_release)
    verify_email = is_enabled(env, EmailVerificationModule) and \
                   EmailVerificationModule(env).email_enabled and \
                   EmailVerificationModule(env).verify_email
    for acct, status in get_user_attribute(env, username=None,
                                           authenticated=None).iteritems():
        account = accounts.get(acct)
        if account is not None and 1 in status:
            # Only use attributes related to authenticated
            # accounts.
            account['name'] = status[1].get('name')
            account['email'] = status[1].get('email')
            # Obfuscate email address if required. 
            if account['email']:
                account['email'] = Chrome(env).format_author(req,
                                                             account['email'])
            approval = status[1].get('approval')
            approval = approval and set((approval,)) or set()
            if approval and filters and not approval.intersection(filters):
                del accounts[acct]
                continue
            if account['email'] and verify_email:
                if email_verified(env, account['username'],
                                  account['email']) == True:
                    if approval:
                        account['approval'] = list(approval)
                elif approval:
                    account['approval'] = list(approval.union(['email']))
                elif not filters or 'email' in filters:
                    account['approval'] = ['email']
            elif approval:
                account['approval'] = list(approval)
    if filters and 'active' not in filters:
        inactive_accounts = {}
        for username in accounts:
            if 'approval' in accounts[username]:
                # Hint: This is 30 % faster than dict.update() here.
                inactive_accounts[username] = accounts[username]
        accounts = inactive_accounts
    ts_seen = last_seen(env)
    for username, last_visit in ts_seen:
        account = accounts.get(username)
        if account and last_visit:
            account['last_visit'] = to_datetime(last_visit)
    return sorted(accounts.itervalues(), key=lambda acct: acct['username'])

def _getoptions(cls):
    opt_cls = isinstance(cls, Component) and cls.__class__ or cls
    options = [(name, value) for name, value in inspect.getmembers(opt_cls)
               if isinstance(value, Option)]
    index = 0
    for option in options:
        index += 1
        try:
            opt_val = option[1].__get__(cls, cls)
        except AttributeError:
            # Error will be raised again when parsing options list,
            # so don't care here.
            continue
        # Check, if option is a valid component (possibly with own options).
        opt_cls = isinstance(opt_val, Component) and opt_val.__class__ or None
        extents = _getoptions(opt_cls)
        for extent in extents:
            options.insert(index, extent)
            index += 1
    return options

def _pre_strip(text):
    """Strip whitespace to prepare multiline strings as pre-formatted text."""
    return '\n'.join([line.strip() for line in text.split('\n')])

def _setorder(req, components):
    """Pull the password store ordering out of the req object"""
    for c in components.get_all_components():
        components[c] = int(req.args.get(c.__class__.__name__, 0))
        continue


class ExtensionOrder(dict):
    """Keeps the order of components in OrderedExtensionsOption."""

    instance = 0

    def __init__(self, d={}, components=[], list=[]):
        self.instance += 1
        self.d = {}
        self.sxref = {}
        for c in components:
            self.d[c] = 0
            self[0] = c
            self.sxref[c.__class__.__name__] = c
            continue
        for i, c in enumerate(list):
            self.d[c] = i + 1
            self[i + 1] = c

    def __getitem__(self, key):
        """Lookup a component in the list."""
        return self.d[key]

    def __setitem__(self, key, value):
        if isinstance(key, Component):
            order = self.d[key]
            self.d[key] = value
            self.d[order].remove(key)
            self[value] = key
        elif isinstance(key, basestring):
            self.d[self.sxref[key]] = value
        elif isinstance(key, int):
            self.d.setdefault(key, [])
            self.d[key].append(value)
        else:
            raise KeyError(_("Invalid key type (%s) for ExtensionOrder")
                             % str(type(key)))
        pass

    def get_enabled_components(self):
        """Return an ordered list of components.

        All components that are order 0 are dropped from the list.
        """
        keys = sorted([k for k in self.d.keys() if isinstance(k, int)])
        component_list = []
        for k in keys[1:]:
            component_list.extend(self.d[k])
            continue
        return component_list

    def get_enabled_component_names(self):
        """Returns the class names of the enabled components."""
        components = self.get_enabled_components()
        return [c.__class__.__name__ for c in components]

    def get_all_components(self):
        return [k for k in self.d.keys() if isinstance(k, Component)]

    def component_count(self):
        return len(self.get_all_components())


class AccountManagerAdminPanel(CommonTemplateProvider):

    implements(IAdminPanelProvider, IAuthenticator)

    ACCTS_PER_PAGE = 5

    auth_init = BoolOption('account-manager', 'auth_init', True,
        doc="Launch an initial Trac authentication setup.")

    def __init__(self):
        self.acctmgr = AccountManager(self.env)
        self.authname = 'setup'
        self.cfg_action = 'ACCTMGR_CONFIG_ADMIN'
        self.guard = AccountGuard(self.env)
        self.perms = PermissionSystem(self.env)

    # IAdminPanelProvider methods

    def get_admin_panels(self, req):
        if req.perm.has_permission('ACCTMGR_CONFIG_ADMIN'):
            yield ('accounts', _("Accounts"), 'config', _("Configuration"))
        if req.perm.has_permission('ACCTMGR_USER_ADMIN'):
            yield ('accounts', _("Accounts"), 'users', _("Users"))

    def render_admin_panel(self, req, cat, page, path_info):
        if page == 'config':
            return self._do_config(req)
        elif page == 'users':
            return self._do_users(req)

    def _do_config(self, req):
        cfg = self.env.config
        env = self.env

        def safe_wiki_to_html(context, text):
            """Convenience function from trac.admin.web_ui."""
            try:
                return format_to_html(env, context, text)
            except Exception, e:
                self.log.error('Unable to render component documentation: %s',
                               exception_to_unicode(e, traceback=True))
            return tag.pre(text)

        data = {
            '_dgettext': dgettext,
            'pretty_precise_timedelta': pretty_precise_timedelta,
            'safe_wiki_to_html': safe_wiki_to_html,
        }

        # Prefer args from URL to make progress bar links work.
        step = req.args.get('step', 0)
        step = int(step and step or req.args.get('active', 0))
        stores = ExtensionOrder(components=self.acctmgr.stores,
                                list=self.acctmgr.password_stores)
        checks = ExtensionOrder(components=self.acctmgr.checks,
                                list=self.acctmgr.register_checks)

        if req.method == 'POST':
            def _redirect(req):
                # Use permission-sensitive redirection on exit.
                if req.perm.has_permission('ACCTMGR_USER_ADMIN'):
                    req.redirect(req.href.admin('accounts', 'users'))
                req.redirect(req.href())
            if req.args.get('exit'):
                try:
                    cfg.parse_if_needed(force=True) # Full reload
                except TypeError:
                    # Attribute was introduced in Trac 0.12, so a fallback
                    # for compatibility down to 0.11 is required.
                    cfg.touch() # Fake write access for reload
                _redirect(req)
            elif req.args.get('restart') and self.acctmgr.refresh_passwd:
                # Don't care as long as the feature is disabled.
                del_user_attribute(self.env, attribute='password_refreshed')
                add_notice(req, _("Password hash refresh procedure restarted."))

        account = dict()
        if req.method == 'POST' and (req.args.get('back') or
                                     req.args.get('next') or
                                     req.args.get('save')):
            # Handling only values for the current page is important.
            if step == 0:
                cfg.set('trac', 'auth_cookie_lifetime',
                        int(req.args.get('auth_cookie_lifetime')))
                cfg.set('trac', 'secure_cookies',
                        bool(req.args.get('secure_cookies', False)))
                cfg.set('trac', 'check_auth_ip',
                        bool(req.args.get('check_auth_ip', False)))
                cfg.set('trac', 'ignore_auth_case',
                        bool(req.args.get('ignore_auth_case', False)))
                acctmgr_login = bool(int(req.args.get('acctmgr_login')))
                # These two can't work in parallel.
                cfg.set('components', 'acct_mgr.web_ui.LoginModule',
                        acctmgr_login and 'enabled' or 'disabled')
                cfg.set('components', 'trac.web.auth.LoginModule',
                        acctmgr_login and 'disabled' or 'enabled')
                if acctmgr_login:
                    cfg.set('account-manager', 'login_opt_list',
                            bool(req.args.get('login_opt_list', False)))
                    cfg.set('account-manager', 'persistent_sessions',
                            bool(req.args.get('persistent_sessions', False)))
                    cfg.set('account-manager', 'cookie_refresh_pct',
                            int(req.args.get('cookie_refresh_pct', False)))
                    cfg.set('trac', 'auth_cookie_path',
                            req.args.get('auth_cookie_path'))

            elif step == 1:
                # This section is as critical as it is complicated by the
                # amount of available options and combinations of options.
                # We restrict initial setup to a single store, allowing to
                # configure additional ones later on in the self-adapting
                # multi-store setup view.
                init_store = req.args.get('init_store')
                init_store_file = req.args.get('init_store_file')
                if init_store:
                    # Define shortcuts for common strings.
                    a = 'account-manager'
                    c = 'components'
                    e = 'enabled'
                    p = 'password_store'
                    # Set minimal required options, leaving most options out
                    # to keep them at - maybe changing - default values.
                    if init_store == 'db':
                        cfg.set(a, p, 'SessionStore')
                        cfg.set(c, 'acct_mgr.db.SessionStore', e)
                        cfg.set(c, 'acct_mgr.pwhash.HtDigestHashMethod', e)
                        from acct_mgr.db import SessionStore
                        from acct_mgr.pwhash import HtDigestHashMethod
                        assert is_enabled(env, HtDigestHashMethod)
                        assert is_enabled(env, SessionStore)
                    elif init_store == 'file':
                        if init_store_file == 'htdigest':
                            cfg.set(a, 'htdigest_file', 'trac.htdigest')
                            cfg.set(a, p, 'HtDigestStore')
                            cfg.set(c, 'acct_mgr.htfile.HtDigestStore', e)
                            from acct_mgr.htfile import HtDigestStore
                            assert is_enabled(env, HtDigestStore)
                        elif init_store_file == 'htpasswd':
                            cfg.set(a, 'htpasswd_file', 'trac.htpasswd')
                            cfg.set(a, 'htpasswd_hash_type', 'md5')
                            cfg.set(a, p, 'HtPasswdStore')
                            cfg.set(c, 'acct_mgr.htfile.HtPasswdStore', e)
                            from acct_mgr.htfile import HtPasswdStore
                            assert is_enabled(env, HtPasswdStore)
                        elif init_store_file == 'svn_file':
                            cfg.set(a, p, 'SvnServePasswordStore')
                            cfg.set(c,
                                'acct_mgr.svnserve.SvnServePasswordStore', e)
                            from acct_mgr.svnserve import SvnServePasswordStore
                            assert is_enabled(env, SvnServePasswordStore)
                    elif init_store == 'http':
                        cfg.set(a, p, 'HttpAuthStore')
                        cfg.set(c, 'acct_mgr.http.HttpAuthStore', e)
                        from acct_mgr.http import HttpAuthStore
                        assert is_enabled(env, HttpAuthStore)
                    # ToDo
                    #elif init_store == 'etc':
                    #    [account-manager]
                    #    password_store =
                    #    [components]
                else:
                    _setorder(req, stores)
                    cfg.set('account-manager', 'password_store',
                            ','.join(stores.get_enabled_component_names()))
                    for store in stores.get_all_components():
                        for attr, option in _getoptions(store):
                            cls_name = store.__class__.__name__
                            newval = req.args.get('%s.%s' % (cls_name, attr))
                            self.log.debug("%s.%s: %s"
                                           % (cls_name, attr, newval))
                            if newval is not None:
                                cfg.set(option.section, option.name, newval)
                    cfg.set('account-manager', 'refresh_passwd',
                        bool(req.args.get('refresh_passwd', False)))
                # Refresh object after changes.
                stores = ExtensionOrder(components=self.acctmgr.stores,
                                        list=self.acctmgr.password_stores)

            elif step == 2:
                reset_password = bool(req.args.get('reset_password', False))
                # Enable the required hash method for this SessionStore too.
                hash_method = cfg.get('account-manager', 'hash_method')
                cfg.set('components', 'acct_mgr.pwhash.%s'
                                      % hash_method, 'enabled')
                cfg.set('components', 'acct_mgr.web_ui.ResetPwStore',
                        reset_password and 'enabled' or 'disabled')
                cfg.set('account-manager', 'reset_password', reset_password)
                cfg.set('account-manager', 'generated_password_length',
                        int(req.args.get('generated_password_length')))
                cfg.set('account-manager', 'force_passwd_change',
                        bool(req.args.get('force_passwd_change', False)))

            elif step == 3:
                acctmgr_register = req.args.get('acctmgr_register', False)
                cfg.set('components', 'acct_mgr.register.RegistrationModule',
                        acctmgr_register and 'enabled' or 'disabled')
                cfg.set('account-manager', 'allow_delete_account',
                        bool(req.args.get('allow_delete_account', False)))
                _setorder(req, checks)
                cfg.set('account-manager', 'register_check',
                        ','.join(checks.get_enabled_component_names()))
                for check in checks.get_all_components():
                    for attr, option in _getoptions(check):
                        cls_name = check.__class__.__name__
                        newval = req.args.get('%s.%s' % (cls_name, attr))
                        self.log.debug("%s.%s: %s" % (cls_name, attr, newval))
                        if newval is not None:
                            cfg.set(option.section, option.name, newval)
                if acctmgr_register:
                    # Should require approval for user self-registrations,
                    # not for accounts created by admin users alone.
                    cfg.set('account-manager', 'require_approval',
                            bool(req.args.get('require_approval', False)))
                # Allow email verification regardless of account creator.
                verify_email = bool(req.args.get('verify_email', False))
                cfg.set('account-manager', 'verify_email', verify_email)
                cfg.set(
                    'components', 'acct_mgr.register.EmailVerificationModule',
                    verify_email and 'enabled' or 'disabled')
                # Refresh object after changes.
                checks = ExtensionOrder(components=self.acctmgr.checks,
                                        list=self.acctmgr.register_checks)
                
            elif step == 4:
                acctmgr_guard = req.args.get('acctmgr_guard', False)
                cfg.set('components', 'acct_mgr.guard.AccountGuard',
                        acctmgr_guard and 'enabled' or 'disabled')
                cfg.set('account-manager', 'login_attempt_max_count',
                        as_int(req.args.get('login_attempt_max_count'),
                        self.guard.login_attempt_max_count, min=0))
                user_lock_time = as_int(req.args.get('user_lock_time'),
                                        self.guard.user_lock_time, min=0)
                cfg.set('account-manager', 'user_lock_time', user_lock_time)
                # AccountGuard.lock_time_progression has the sanitized value.
                cfg.set('account-manager', 'user_lock_time_progression',
                        req.args.get('user_lock_time_progression') or \
                        self.guard.lock_time_progression)
                cfg.set('account-manager', 'user_lock_max_time',
                        as_int(req.args.get('user_lock_max_time'),
                        self.guard.user_lock_max_time, min=user_lock_time))

            if req.args.get('save') and step == 5:
                perms = self.perms.get_user_permissions(self.authname)
                if perms.get(self.cfg_action) and perms[self.cfg_action]:
                    # Revoke initial configuration permission.
                    self.perms.revoke_permission(self.authname,
                                                 self.cfg_action)
                    # Restore 'authenticated' users permissions.
                    perms = self.perms.get_user_permissions('auth_moved')
                    for action in perms:
                        # Filter actions inherited from 'anonymous'.
                        if perms[action] and \
                                action not in PermissionCache(self.env):
                            self.perms.grant_permission('authenticated', action)
                            self.perms.revoke_permission('auth_moved', action)
                # Prevent to run another initial setup later.
                cfg.set('account-manager', 'auth_init', False)
                # Write changes back to file to make them permanent, what
                # causes the environment to reload on following redirect.
                cfg.save()
                add_notice(req, _("Your changes have been saved."))
                _redirect(req)
            else:
                add_notice(req, _(
                    "Your changes are cached until you either drop or save "
                    "them all (see last step)."))

        if req.method == 'POST' and req.args.get('add'):
            # Initial admin account requested.
            account = self._do_add(req)
            username = self.acctmgr.handle_username_casing(
                           req.args.get('username', '').strip())
            if not account and username:
                self.perms.grant_permission(username, 'TRAC_ADMIN')

        # Prepare information for progress bar and page navigation.
        if req.method == 'POST':
            if 'next' in req.args:
                step += 1
            elif ('back' in req.args or 'prev' in req.args) and step > 0:
                step -= 1
        steps = [
            dict(label=_("Authentication Options"), past=step>0),
            dict(image='users', label=_("Password Store"), past=step > 1),
            dict(image='refresh', label=_("Password Policy"), past=step > 2),
            dict(image='approval', label=_("Account Policy"), past=step > 3),
            dict(image='guard', label=_("Account Guard"), past=step > 4),
            dict(label=_("Initialization"))
        ]
        data.update({
            'active': step, 'steps': steps,

            'auth_cookie_lifetime': cfg.getint('trac',
                                               'auth_cookie_lifetime'),
            'secure_cookies': cfg.getbool('trac', 'secure_cookies'),
            'check_auth_ip': cfg.getbool('trac', 'check_auth_ip'),
            'ignore_auth_case': cfg.getbool('trac', 'ignore_auth_case'),
            'acctmgr_login': cfg.getbool('components',
                                         'acct_mgr.web_ui.LoginModule'),
            'login_opt_list': cfg.getbool('account-manager',
                                          'login_opt_list'),
            'persistent_sessions': self.acctmgr.persistent_sessions,
            'cookie_refresh_pct': cfg.getint('account-manager',
                                             'cookie_refresh_pct'),
            'auth_cookie_path': cfg.get('trac', 'auth_cookie_path'),
            })

        # Build password store configuration details.
        disabled_store = None
        password_store = cfg.getlist('account-manager', 'password_store')
        data.update({'password_store': password_store})
        if password_store:
            store_count = range(0, stores.component_count() + 1)
            store_list = []
            for store in self.acctmgr.stores:
                if store.__class__.__name__ == "ResetPwStore":
                    # Exclude special store, that is used strictly internally
                    # and inherits configuration from SessionStore anyway.
                    continue
                options = []
                for attr, option in _getoptions(store):
                    error = None
                    opt_val = None
                    value = None
                    try:
                        opt_val = option.__get__(store, store)
                    except AttributeError, e:
                        env.log.error(e)
                        regexp = r'^.* interface named \"(.*?)\".*$'
                        error = _("Error while reading configuration - Hint: "
                                  "Enable/install required component '%s'."
                                  % re.sub(regexp, r'\1', str(e)))
                        pass
                    if opt_val:
                        value = isinstance(opt_val, Component) and \
                                opt_val.__class__.__name__ or opt_val
                    opt_sel = None
                    try:
                        interface = option.xtnpt.interface
                        opt_sel = {'options': [], 'selected': None}
                    except AttributeError:
                        # No ExtensionOption / Interface undefined.
                        pass
                    if opt_sel:
                        for impl in option.xtnpt.extensions(env):
                            extension = impl.__class__.__name__
                            opt_sel['options'].append(extension)
                            if opt_val and extension == value:
                                opt_sel['selected'] = extension
                        if len(opt_sel['options']) == 0 and error:
                            opt_sel['error'] = error
                        value = opt_sel
                    options.append({
                        'label': attr,
                        'name': '%s.%s' % (store.__class__.__name__, attr),
                        'value': value,
                        'doc': gettext(option.__doc__)
                    })
                    continue
                store_list.append({
                    'name': store.__class__.__name__,
                    'classname': store.__class__.__name__,
                    'order': stores[store],
                    'options': options
                })
                continue
            store_list = sorted(store_list, key=lambda i: i['order'])
            disabled_store = frozenset(password_store).difference(frozenset(
                             [store['classname'] for store in store_list]))
            data.update({
                'store_count': store_count,
                'disabled_store': disabled_store,
                'store_list': store_list,
                'refresh_passwd': self.acctmgr.refresh_passwd,
            })
        else:
            # Prepare initial setup information.
            data.update({
                'init_store': 'db',
                'init_store_hint': dict(
                    db = _pre_strip("""
                        [account-manager]
                        db_htdigest_realm =
                        password_store = SessionStore

                        [components]
                        acct_mgr.db.SessionStore = enabled
                        acct_mgr.pwhash.HtDigestHashMethod = enabled
                        """),
                    htdigest = _pre_strip("""
                        [account-manager]
                        htdigest_file = trac.htdigest
                        htdigest_realm =
                        password_store = HtDigestStore

                        [components]
                        acct_mgr.htfile.HtDigestStore = enabled
                        """),
                    htpasswd = _pre_strip("""
                        [account-manager]
                        htpasswd_file = trac.htpasswd
                        htpasswd_hash_type = md5
                        password_store = HtPasswdStore

                        [components]
                        acct_mgr.htfile.HtPasswdStore = enabled
                        """),
                    svn_file = _pre_strip("""
                        [account-manager]
                        password_file =
                        password_store = SvnServePasswordStore

                        [components]
                        acct_mgr.svnserve.SvnServePasswordStore = enabled
                        """),
                    http = _pre_strip("""
                        [account-manager]
                        auth_url =
                        password_store = HttpAuthStore

                        [components]
                        acct_mgr.http.HttpAuthStore = enabled
                        """),
                    etc = _pre_strip("""
                        [account-manager]
                        password_store =

                        [components]
                        """)
                ),
            })

        reset_password = cfg.getbool('account-manager', 'reset_password')
        data.update({
            'reset_password': reset_password,
            'generated_password_length': cfg.getint('account-manager',
                                             'generated_password_length'),
            'force_passwd_change': cfg.getbool('account-manager',
                                               'force_passwd_change'),
        })

        # Build registration check configuration details.
        acctmgr_register = cfg.getbool('components',
                                       'acct_mgr.register.RegistrationModule')
        check_list = []
        for check in self.acctmgr.checks:
            options = []
            for attr, option in _getoptions(check):
                error = None
                opt_val = None
                value = None
                try:
                    opt_val = option.__get__(check, check)
                except AttributeError, e:
                    env.log.error(e)
                    regexp = r'^.* interface named \"(.*?)\".*$'
                    error = _("Error while reading configuration - "
                              "Hint: Enable/install required component '%s'."
                              % re.sub(regexp, r'\1', str(e)))
                    pass
                if opt_val:
                    value = isinstance(opt_val, Component) and \
                            opt_val.__class__.__name__ or opt_val
                opt_sel = None
                try:
                    interface = option.xtnpt.interface
                    opt_sel = {'options': [], 'selected': None}
                except AttributeError:
                    # No ExtensionOption / Interface undefined.
                    pass
                if opt_sel:
                    for impl in option.xtnpt.extensions(env):
                        extension = impl.__class__.__name__
                        opt_sel['options'].append(extension)
                        if opt_val and extension == value:
                            opt_sel['selected'] = extension
                    if len(opt_sel['options']) == 0 and error:
                        opt_sel['error'] = error
                    value = opt_sel
                options.append({
                    'label': attr,
                    'name': '%s.%s' % (check.__class__.__name__, attr),
                    'value': value,
                    'doc': gettext(option.__doc__)
                })
                continue
            # Fallback for check components not derived from
            # acct_mgr.register.GenericRegistrationInspector.
            try:
                doc = gettext(check.doc)
            except AttributeError:
                doc = check.__class__.__doc__
            check_list.append({
                'name': check.__class__.__name__,
                'classname': check.__class__.__name__,
                'doc': doc,
                'order': checks[check],
                'options': options
            })
            continue
        check_list = sorted(check_list, key=lambda i: i['order'])
        check_count = range(0, checks.component_count() + 1)
        register_check = cfg.getlist('account-manager', 'register_check')
        disabled_check = frozenset(register_check).difference(frozenset(
                         [check['classname'] for check in check_list]))
        data.update({
            'acctmgr_register': acctmgr_register,
            'allow_delete_account': cfg.getbool('account-manager',
                                                'allow_delete_account'),
            'register_check': register_check,
            'disabled_check': disabled_check,
            'check_list': check_list,
            'check_count': check_count,
            'require_approval': cfg.getbool('account-manager',
                                            'require_approval'),
            'verify_email': EmailVerificationModule(env).verify_email,
        })

        # Prepare AccountGuard configuration details.
        acctmgr_guard = (
            cfg.getbool('components', 'acct_mgr.web_ui.LoginModule') and
            cfg.getbool('components', 'acct_mgr.guard.AccountGuard')
        )
        login_attempt_max_count = self.guard.login_attempt_max_count
        data.update({
            'acctmgr_guard': acctmgr_guard,
            'login_attempt_max_count': login_attempt_max_count,
            'user_lock_time': self.guard.user_lock_time,
            'user_lock_max_time': self.guard.user_lock_max_time,
            'user_lock_time_progression': self.guard.lock_time_progression,
        })

        # Prepare configuration check-up information.
        details = []
        status = (disabled_store and 'error' or not password_store and
                  'disabled' or 'ok')
        details.append(dict(desc=_("Password Store"), status=status, step=1))
        # Require no pending password store configuration issues.
        ready = status != 'error' and True or False
        
        details.append(dict(
            desc=_("Password Reset"),
            status=not reset_password and 'disabled' or 'ok',
            step=2
            )
        )
        status = (disabled_check and 'error' or not register_check and
                  'unknown' or not acctmgr_register and 'disabled' or 'ok')
        details.append(
            dict(desc=_("Account Registration"), status=status, step=3)
        )
        # Require no pending registration check configuration issues.
        ready = ready and status != 'error' and True or False

        details.append(dict(
            desc=_("Account Guard"),
            status=((not acctmgr_guard or login_attempt_max_count < 1) and
                    'disabled' or 'ok'),
            step=4)
        )
        admin_available = self.perms.get_users_with_permission(
                              'TRAC_ADMIN') and True or False
        status = not admin_available and 'error' or 'ok'
        details.append(dict(desc=_("Admin user account"), status=status))
        # Require at least one admin account.
        ready = ready and status != 'error' and True or False

        details.append(dict(desc=_("Configuration Review"), status='unknown'))
        data.update({
            'admin_available': admin_available,
            'acctmgr': account,
            'set_password': self.acctmgr.supports('set_password'),
            'completion': dict(details=details, ready=ready),
        })

        # Extract relevant configuration options for final review.
        opts = [(k, v) for k, v in cfg['account-manager'].options()]
        roundup = {'account-manager': sorted(opts)}
        components = ['trac.web.auth.LoginModule']
        core_opts = (
            'auth_cookie_path', 'auth_cookie_lifetime', 'ignore_auth_case',
            'check_auth_ip', 'secure_cookies'
        )
        opts = [(k, v) for k, v in cfg['trac'].options() if k in core_opts]
        roundup['trac'] = sorted(opts)
        # Read sections marked as related too.
        components.extend(cfg['account-manager'].getlist('sibling_cmp'))
        roundup['components'] = [(k, v) for k, v in
                                 cfg['components'].options()
                                 if k.startswith('acct_mgr') or
                                 k in [c.lower() for c in components]]
        if 'sibling_cfg' in cfg['account-manager']:
            siblings = cfg['account-manager'].getlist('sibling_cfg')
            for sibling in siblings:
                opts = [(k, v) for k, v in cfg[sibling].options()]
                roundup[sibling] = sorted(opts)
        # Clean-up by filtering options with default values.
        roundup_defaults = dict()
        for section in roundup:
            defaults = cfg.defaults().get(section)
            for option in roundup[section]:
                if defaults and option[0] in defaults and \
                        defaults[option[0]] == option[1]:
                    if section in roundup_defaults:
                        roundup_defaults[section].append(option[0])
                    else:
                        roundup_defaults[section] = list((option[0],))
        data.update(dict(roundup=roundup, roundup_defaults=roundup_defaults))

        add_script(req, 'acct_mgr/acctmgr_admin.js')
        add_stylesheet(req, 'acct_mgr/acctmgr.css')
        add_stylesheet(req, 'common/css/report.css')
        return 'admin_accountsconfig.html', data

    def _do_users(self, req):
        env = self.env
        acctmgr = self.acctmgr
        acctmod = AccountModule(env)
        guard = self.guard
        listing_enabled = acctmgr.supports('get_users')
        password_change_enabled = acctmgr.supports('set_password')
        password_reset_enabled = acctmod.reset_password_enabled
        delete_enabled = acctmgr.supports('delete_user')
        verify_enabled = EmailVerificationModule(env).email_enabled and \
                         EmailVerificationModule(env).verify_email
        data = {
            '_dgettext': dgettext,
            'acctmgr': dict(), 'email_approved': True, 'filters': [],
            'listing_enabled': listing_enabled,
            'create_enabled': acctmgr.supports('set_password'),
            'delete_enabled': delete_enabled,
            'verify_enabled': verify_enabled,
            'ignore_auth_case': self.config.getbool('trac',
                                                    'ignore_auth_case'),
            'password_change_enabled': password_change_enabled,
            'password_reset_enabled': password_reset_enabled
        }
        if req.method == 'GET':
            if 'user' in req.args.iterkeys():
                return self._do_acct_details(req)
            elif req.args.get('max_per_page'):
                return self._do_db_cleanup(req)

        if req.method == 'POST':
            email_approved = req.args.get('email_approved')
            # Preserve selection during a series of requests.
            data['email_approved'] = email_approved

            sel = req.args.get('sel')
            sel = isinstance(sel, list) and sel or [sel]
            if req.args.get('add'):
                # Add new user account.
                data['acctmgr'] = self._do_add(req)

            elif req.args.get('approve') and req.args.get('sel'):
                # Toggle approval status for selected accounts.
                ban = []
                unban = []
                for username in sel:
                    # Get account approval status.
                    status = get_user_attribute(env, username,
                                                attribute='approval')
                    status = username in status and \
                             status[username][1].get('approval') or None
                    if status:
                        # Admit authenticated/registered session.
                        del_user_attribute(env, username,
                                           attribute='approval')
                        unban.append(username)
                    else:
                        # Ban the account.
                        set_user_attribute(env, username, 'approval',
                                           N_('revoked'))
                        ban.append(username)
                msg = None
                if unban:
                    accounts = tag.b(', '.join(unban))
                    msg = ngettext("Approved account: %(accounts)s",
                                   "Approved accounts: %(accounts)s",
                                   len(unban), accounts=accounts)
                if ban:
                    if msg:
                        msg = tag(Markup(msg), Markup('<br />'))
                    else:
                        msg = tag()
                    accounts = tag.b(', '.join(ban))
                    msg(Markup(ngettext("Banned account: %(accounts)s",
                                        "Banned accounts: %(accounts)s",
                                        len(ban), accounts=accounts)))
                if ban or unban:
                    add_notice(req, Markup(msg))
            elif req.args.get('reset') and req.args.get('sel'):
                # Password reset for one or more accounts.
                if password_reset_enabled:
                    for username, name, email in env.get_known_users():
                        if username in sel:
                            acctmod._reset_password(req, username, email)
                    if sel:
                        add_notice(req, Markup(_(
                                   "Password reset for %(accounts)s.",
                                   accounts=tag.b(', '.join(sel)))))
                else:
                    add_warning(req, _(
                        "The password reset procedure is not enabled."))
            elif req.args.get('remove') and req.args.get('sel'):
                # Delete one or more accounts.
                if delete_enabled:
                    for account in sel:
                        acctmgr.delete_user(account)
                    if sel:
                        add_notice(req, Markup(ngettext(
                            "Deleted account: %(accounts)s",
                            "Deleted accounts: %(accounts)s",
                            len(sel), accounts=tag.b(', '.join(sel)))))
                else:
                    add_warning(req, _(
                        "The password store does not support deleting users."))
            elif req.args.get('change'):
                # Change attributes and or password of existing user account.
                attributes = {
                    'email': _("Email Address"),
                    'name': _("Pre-/Surname (Nickname)"),
                    'password': _("Password")
                    }
                error = TracError('')
                success = []
                username = acctmgr.handle_username_casing(
                                   req.args.get('username').strip())
                try:
                    if not username:
                        error.account = {'username' : username}
                        error.message = _("Username cannot be empty.")
                        raise error

                    if not acctmgr.has_user(username):
                        error.account = {'username' : username}
                        error.message = Markup(_("Unknown user %(user)s.",
                                                 user=tag.b(username)))
                        raise error

                    password = req.args.get('password')
                    if password and (password.strip() != ''):
                        if password_change_enabled:
                            if password != req.args.get('password_confirm'):
                                error.message = _("The passwords must match.")
                                raise error
                            acctmgr.set_password(username, password)
                            success.append(attributes.get('password'))
                        else:
                            add_warning(req, _(
                                "The password store does not support "
                                "changing passwords."))
                    for attribute in ('name', 'email'):
                        value = req.args.get(attribute, '').strip()
                        if value:
                            set_user_attribute(env, username,
                                               attribute, value)
                            success.append(attributes.get(attribute))
                            # Account email approval for authoritative action.
                            if attribute == 'email' and verify_enabled and \
                                    email_approved:
                                set_user_attribute(env, username,
                                    'email_verification_sent_to', value)
                    if success:
                        attributes = tag.b(', '.join(success))
                        add_notice(req, Markup(_(
                                   "Updated %(attributes)s for %(username)s.",
                                   attributes=attributes,
                                   username=tag.b(username))))
                    # User editor form clean-up on success.
                    data['acctmgr'] = {}
                except TracError, e:
                    add_warning(req, e.message)
                    data['acctmgr'] = getattr(e, 'account', '')
            elif len([action for action in req.args.iterkeys() \
                      if action in ('cleanup' 'purge' 'unselect')]) > 0:
                return self._do_db_cleanup(req)

        # (Re-)Build current user list.
        available_filters = [
            ('active', _("active")),
            ('revoked', _("revoked"), False), # not shown by default
            ('pending', _("pending approval"))
        ]
        if verify_enabled:
            available_filters.append(('email', _("email unverified")))
        # Check request or session for enabled filters, or use default.
        filters = [f[0] for f in available_filters
                   if 'filter_%s' % f[0] in req.args]
        key = 'acctmgr_user.filter.%s'
        if not filters:
            filters = [f[0] for f in available_filters
                       if req.session.get(key % f[0]) == '1']
        if not filters:
                filters = [f[0] for f in available_filters
                           if len(f) == 2 or f[2]]
        for filter_ in available_filters:
            data['filters'].append({'name': filter_[0], 'label': filter_[1],
                                    'enabled': filter_[0] in filters})
        if listing_enabled:
            data.update({
                'accounts': fetch_user_data(env, req, filters),
                'cls': 'listing',
                'cols': ['email', 'name'],
                'delete_msg_confirm': _(
                    "Are you sure you want to delete these accounts?")})

            # Save results of submitted user list filter form to the session.
            if 'update' in req.args:
                for filter in available_filters:
                    key = 'acctmgr_user.filter.%s' % filter[0]
                    if 'filter_%s' % filter[0] in req.args:
                        req.session[key] = '1'
                    elif key in req.session:
                        del req.session[key]
                req.redirect(req.href.admin('accounts', 'users'))

            # Prevent IRequestFilter in trac.timeline.web_ui.TimelineModule
            #   of Trac 0.13 and later from adding a link to timeline by
            #   adding the function with a different key name here.
            data['pretty_date'] = get_pretty_dateinfo(env, req)
        add_stylesheet(req, 'acct_mgr/acctmgr.css')
        add_stylesheet(req, 'common/css/report.css')
        return 'admin_users.html', data

    def _do_acct_details(self, req):
        username = req.args.get('user')
        if not username:
            # Accessing user account details without username is not useful,
            # so we revert such request immediately. 
            add_warning(req, _(
                "Please choose account by username from the list to proceed."
                ))
            req.redirect(req.href.admin('accounts', 'users'))

        acctmgr = self.acctmgr
        guard = self.guard

        data = dict(_dgettext=dgettext, user=username)

        stores = ExtensionOrder(components=self.acctmgr.stores,
                                list=self.acctmgr.password_stores)
        user_store = acctmgr.find_user_store(username)
        if not user_store is None:
            data['user_store'] = user_store.__class__.__name__
            data['store_order_num'] = stores[user_store]
        data['ignore_auth_case'] = \
            self.config.getbool('trac', 'ignore_auth_case')

        for username_, name, email in self.env.get_known_users():
            if username_ == username:
                data['name'] = name
                if email:
                    data['email'] = email
                break
        ts_seen = last_seen(self.env, username)
        if ts_seen and ts_seen[0][1]:
            data['last_visit'] = format_datetime(ts_seen[0][1], tzinfo=req.tz)

        if is_enabled(self.env, EmailVerificationModule) and \
                EmailVerificationModule(self.env).verify_email:
            data['verification'] = 'enabled'
            data['email_verified'] = email_verified(self.env, username, email)
            self.log.debug('AcctMgr:admin:_do_acct_details for user \"' + \
                username + '\", email \"' + str(email) + '\": ' + \
                str(data['email_verified']))

        if is_enabled(self.env, AccountGuard):
            attempts = []
            attempts_count = guard.failed_count(username, reset=None)
            if attempts_count > 0:
                for attempt in guard.get_failed_log(username):
                    t = format_datetime(to_datetime(
                                             attempt['time']), tzinfo=req.tz)
                    attempts.append({'ipnr': attempt['ipnr'], 'time': t})
                data['attempts'] = attempts
                data['pretty_lock_time'] = guard.pretty_lock_time(username,
                                                                  next=True)
            data['attempts_count'] = attempts_count
            data['lock_count'] = guard.lock_count(username)
            if guard.user_locked(username) is True:
                data['user_locked'] = True
                data['release_time'] = guard.pretty_release_time(req, username)

        status = []
        if self.config.getbool('account-manager', 'require_approval'):
            status = get_user_attribute(self.env, username,
                                        attribute='approval')
        approval = username in status and \
                   status[username][1].get('approval') or None

        if req.args.get('delete') or req.args.get('release'):
            changed = False
            if approval and req.args.get('release'):
                # Admit authenticated/registered session.
                del_user_attribute(self.env, username, attribute='approval')
                add_notice(req, Markup(_(
                    "Account lock (%(condition)s) for user %(user)s cleared",
                    condition=gettext(approval), user=tag.b(username))))
                changed = True
            # Delete failed login attempts, evaluating attempts count.
            if guard.failed_count(username, reset=True) > 0:
                add_notice(req, Markup(_(
                    "Failed login attempts for user %(user)s deleted",
                    user=tag.b(username))))
                changed = True
            if changed:
                req.redirect(req.href.admin('accounts', 'users',
                                            user=username))
        data['approval'] = approval

        add_stylesheet(req, 'acct_mgr/acctmgr.css')
        add_ctxtnav(req, _("Back to Accounts"),
                    href=req.href.admin('accounts', 'users'))
        data['url'] = req.href.admin('accounts', 'users', user=username)
        return 'account_details.html', data

    def _do_add(self, req):
        """Add new user account on verified request."""
        env = self.env
        acctmgr = self.acctmgr
        account = dict(email=req.args.get('email', '').strip(),
                       name=req.args.get('name', '').strip(),
                       username=acctmgr.handle_username_casing(
                                    req.args.get('username', '').strip()))
        verify_enabled = EmailVerificationModule(env).email_enabled and \
                         EmailVerificationModule(env).verify_email
        
        if acctmgr.supports('set_password'):
            if account['username']:
                # Check request and prime account on success.
                try:
                    acctmgr.validate_registration(req)
                    # Account email approval for authoritative action.
                    if verify_enabled and account['email'] and \
                            req.args.get('email_approved'):
                        set_user_attribute(env, account['username'],
                            'email_verification_sent_to', account['email'])
                    add_notice(req, Markup(tag_(
                               "Account %(username)s created.",
                               username=tag.b(account['username']))))
                    # User editor form clean-up.
                    account = {}
                except RegistrationError, e:
                    # Attempt deferred translation.
                    message = gettext(e.message)
                    # Check for (matching number of) message arguments
                    #   before attempting string substitution.
                    if e.msg_args and \
                            len(e.msg_args) == len(re.findall('%s', message)):
                        message = message % e.msg_args
                    add_warning(req, Markup(message))
        else:
            add_warning(req, _(
                "The password store does not support creating users."))
        return account

    def _do_db_cleanup(self, req):
        if req.perm.has_permission('ACCTMGR_ADMIN'):
            env = self.env
            changed = False
            # Get all data from 'session_attributes' db table.
            attr = get_user_attribute(self.env, username=None,
                                      authenticated=None)
            attrs = {}
            sel = req.args.get('sel')
            if req.args.get('purge') and sel is not None:
                sel = isinstance(sel, list) and sel or [sel]
                sel_len = len(sel)
                matched = []
                for acct, states in attr.iteritems():
                    for state in states['id'].keys():
                        for elem, id in states[state]['id'].iteritems():
                            if id in sel:
                                if acct in attrs.keys():
                                    if state in attrs[acct].keys():
                                        attrs[acct][state] \
                                            .append(elem)
                                    else:
                                        attrs[acct][state] = [elem]
                                else:
                                    attrs[acct] = {state: [elem]}
                                matched.append(id)
                                if len(matched) == sel_len:
                                    break
                        if len(matched) == sel_len:
                            break
                    if len(matched) == sel_len:
                        break
                for id in (frozenset(sel) - frozenset(matched)):
                    for acct, states in attr.iteritems():
                        for state, id_ in states['id'].iteritems():
                            if id == id_:
                                # Full account is marked, forget attributes.
                                if acct in attrs.keys():
                                    attrs[acct].update({state: []})
                                else:
                                    attrs[acct] = {state: []}
                                matched.append(id)
                                if len(matched) == sel_len:
                                    break
                        if len(matched) == sel_len:
                            break
                # DEVEL: for Python>2.4 better use defaultdict for counters
                del_count = {'acct': 0, 'attr': 0}
                for account, states in attrs.iteritems():
                    for state, elem in states.iteritems():
                        if len(elem) == 0:
                            del_user_attribute(env, account, state)
                            del_count['acct'] += 1
                        else:
                            for attribute in elem:
                                del_user_attribute(env, account, state,
                                                   attribute)
                                del_count['attr'] += 1
                    changed = True

            if changed == True:
                # Update the dict after changes.
                attr = get_user_attribute(env, username=None,
                                          authenticated=None)
            data = {'_dgettext': dgettext}
            data.update(self._prepare_attrs(req, attr))

            if req.args.get('purge') and sel is not None:
                accounts = attributes = ''
                n_plural=del_count['acct']
                if n_plural > 0:
                    accounts = tag.li(tag.span(tag(ngettext(
                    "%(count)s account",
                    "%(count)s accounts",
                    n_plural, count=n_plural
                ))))
                n_plural=del_count['attr']
                if n_plural > 0:
                    attributes = tag.li(tag.span(tag(ngettext(
                    "%(count)s account attribute",
                    "%(count)s account attributes",
                    n_plural, count=n_plural
                ))))
                data['result'] = tag(_("Successfully deleted:"),
                                     tag.ul(accounts, attributes))
            add_ctxtnav(req, _("Back to Accounts"),
                        href=req.href.admin('accounts', 'users'))
            add_stylesheet(req, 'acct_mgr/acctmgr.css')
            return 'db_cleanup.html', data

    def _prepare_attrs(self, req, attr):
        page = int(req.args.get('page', '1'))
        # Paginator can't deal with dict, so convert to list.
        attr_lst = [(k,v) for k,v in attr.iteritems()]
        max_per_page = as_int(req.args.get('max_per_page'), None)
        if max_per_page is None:
            max_per_page = self.ACCTS_PER_PAGE
        attr = Paginator(attr_lst, page - 1, max_per_page)

        pagedata = []
        shown_pages = attr.get_shown_pages(21)
        for shown_page in shown_pages:
            page_href = req.href.admin('accounts', 'users', page=shown_page,
                                       max_per_page=max_per_page)
            pagedata.append([page_href, None, str(shown_page),
                             _("page %(num)s", num=str(shown_page))])

        fields = ['href', 'class', 'string', 'title']
        attr.shown_pages = [dict(zip(fields, p)) for p in pagedata]

        attr.current_page = {'href': None, 'class': 'current',
                             'string': str(attr.page + 1), 'title':None}

        if attr.has_next_page:
            next_href = req.href.admin('accounts', 'users', page=page + 1,
                                       max_per_page=max_per_page)
            add_link(req, 'next', next_href, _('Next Page'))

        if attr.has_previous_page:
            prev_href = req.href.admin('accounts', 'users', page=page - 1,
                                       max_per_page=max_per_page)
            add_link(req, 'prev', prev_href, _('Previous Page'))
        page_href = req.href.admin('accounts', 'cleanup')
        return {'attr': attr, 'page_href': page_href}

    # IAuthenticator method
    def authenticate(self, req):
        """Launch an initial Trac authentication setup.

        This method authorizes the first login request after Trac environment
        load as setup session, while no user has full permissions, but can
        be locked by configuration to never authenticate at all.
        """
        init = self.env.config.getbool('account-manager', 'auth_init')
        remote_user = None

        if init and req.path_info == '/login' and not req.remote_user and \
                not self.perms.get_users_with_permission('TRAC_ADMIN'):
            # Prevent to run another initial setup in parallel.
            self.env.config.set('account-manager', 'auth_init', False)
            # Initialize a setup session.
            req.environ['REMOTE_USER'] = remote_user = self.authname
            if not self.authname in \
                    self.perms.get_users_with_permission(self.cfg_action):
                self.perms.grant_permission(self.authname, self.cfg_action)
            # Do not grant anything but the required configuration permission.
            perms = self.perms.get_user_permissions('authenticated')
            for action in perms:
                # Filter actions inherited from 'anonymous'.
                if perms[action] and action not in PermissionCache(self.env):
                    self.perms.grant_permission('auth_moved', action)
                    self.perms.revoke_permission('authenticated', action)
            add_notice(req, _("Initial Trac authentication setup launched."))
            # Set referer without interfering with redirect to '/login'.
            req.args['referer'] = req.href.admin('accounts', 'config')
        return remote_user
