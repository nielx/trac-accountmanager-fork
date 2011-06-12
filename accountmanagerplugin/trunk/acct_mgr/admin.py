# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

import inspect

from genshi.builder     import tag
from genshi.core        import Markup
from pkg_resources      import resource_filename

from trac.core          import *
from trac.config        import Option
from trac.perm          import IPermissionRequestor, PermissionSystem
from trac.util.datefmt  import format_datetime, to_datetime
from trac.web.chrome    import ITemplateProvider, add_notice, \
                               add_stylesheet, add_warning
from trac.admin         import IAdminPanelProvider

from acct_mgr.api       import _, tag_, AccountManager
from acct_mgr.guard     import AccountGuard
from acct_mgr.web_ui    import _create_user, EmailVerificationModule


def _getoptions(cls):
    if isinstance(cls, Component):
        cls = cls.__class__
    return [(name, value) for name, value in inspect.getmembers(cls)
            if isinstance(value, Option)]

def _setorder(req, stores):
    """Pull the password store ordering out of the req object"""
    for store in stores.get_all_stores():
        stores[store] = int(req.args.get(store.__class__.__name__, 0))
        continue


class StoreOrder(dict):
    """Keeps the order of the Password Stores"""

    instance = 0

    def __init__(self, d={}, stores=[], list=[]):
        self.instance += 1
        self.d = {}
        self.sxref = {}
        for store in stores:
            self.d[store] = 0
            self[0] = store
            self.sxref[store.__class__.__name__] = store
            continue
        for i, s in enumerate(list):
            self.d[s] = i + 1
            self[i + 1] = s

    def __getitem__(self, key):
        """Lookup a store in the list"""
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
            raise KeyError(_("Invalid key type (%s) for StoreOrder")
                             % str(type(key)))
        pass

    def get_enabled_stores(self):
        """Return an ordered list of password stores

        All stores that are order 0 are dropped from the list.
        """
        keys = [k for k in self.d.keys() if isinstance(k, int)]
        keys.sort()
        storelist = []
        for k in keys[1:]:
            storelist.extend(self.d[k])
            continue
        return storelist

    def get_enabled_store_names(self):
        """Returns the class names of the enabled password stores"""
        stores = self.get_enabled_stores()
        return [s.__class__.__name__ for s in stores]

    def get_all_stores(self):
        return [k for k in self.d.keys() if isinstance(k, Component)]

    def numstores(self):
        return len(self.get_all_stores())


class AccountManagerAdminPage(Component):

    implements(IPermissionRequestor, IAdminPanelProvider, ITemplateProvider)

    def __init__(self):
        self.account_manager = AccountManager(self.env)
        self.account_guard = AccountGuard(self.env)

    # IPermissionRequestor
    def get_permission_actions(self):
        action = ['ACCTMGR_CONFIG_ADMIN', 'ACCTMGR_USER_ADMIN']
        actions = [('ACCTMGR_ADMIN', action), action[0], action[1],]
        return actions

    # IAdminPanelProvider
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
        stores = StoreOrder(stores=self.account_manager.stores,
                            list=self.account_manager.password_store)
        if req.method == 'POST':
            _setorder(req, stores)
            self.config.set('account-manager', 'password_store',
                            ','.join(stores.get_enabled_store_names()))
            for store in stores.get_all_stores():
                for attr, option in _getoptions(store):
                    newvalue = req.args.get('%s.%s' % (store.__class__.__name__, attr))
                    self.log.debug("%s.%s: %s" % (store.__class__.__name__, attr, newvalue))
                    if newvalue is not None:
                        self.config.set(option.section, option.name, newvalue)
                        self.config.save()
            self.config.set('account-manager', 'force_passwd_change',
                            req.args.get('force_passwd_change', False))
            self.config.set('account-manager', 'persistent_sessions',
                            req.args.get('persistent_sessions', False))
            self.config.set('account-manager', 'verify_email',
                            req.args.get('verify_email', False))
            self.config.set('account-manager', 'refresh_passwd',
                            req.args.get('refresh_passwd', False))
            self.config.save()
        sections = []
        for store in self.account_manager.stores:
            if store.__class__.__name__ == "ResetPwStore":
                # Exclude special store, that is used strictly internally and
                # inherits configuration from SessionStore anyway.
                continue
            options = []
            for attr, option in _getoptions(store):
                opt_val = option.__get__(store, store)
                opt_val = isinstance(opt_val, Component) and \
                          opt_val.__class__.__name__ or opt_val
                options.append(
                            {'label': attr,
                            'name': '%s.%s' % (store.__class__.__name__, attr),
                            'value': opt_val,
                            'doc': option.__doc__
                            })
                continue
            sections.append(
                        {'name': store.__class__.__name__,
                        'classname': store.__class__.__name__,
                        'order': stores[store],
                        'options' : options,
                        })
            continue
        sections = sorted(sections, key=lambda i: i['name'])
        numstores = range(0, stores.numstores() + 1)
        data = {
            'sections': sections,
            'numstores': numstores,
            'force_passwd_change': self.account_manager.force_passwd_change,
            'persistent_sessions': self.account_manager.persistent_sessions,
            'verify_email': self.account_manager.verify_email,
            'refresh_passwd': self.account_manager.refresh_passwd,
            }
        return 'admin_accountsconfig.html', data

    def _do_users(self, req):
        perm = PermissionSystem(self.env)
        mgr = self.account_manager
        guard = self.account_guard
        listing_enabled = mgr.supports('get_users')
        create_enabled = mgr.supports('set_password')
        password_change_enabled = mgr.supports('set_password')
        delete_enabled = mgr.supports('delete_user')

        data = {
            'listing_enabled': listing_enabled,
            'create_enabled': create_enabled,
            'delete_enabled': delete_enabled,
            'password_change_enabled': password_change_enabled,
            'acctmgr' : { 'username' : None,
                          'name' : None,
                          'email' : None,
                        }
        }

        if req.method == 'POST':
            if req.args.get('add'):
                if create_enabled:
                    try:
                        _create_user(req, self.env, check_permissions=False)
                    except TracError, e:
                        data['registration_error'] = e.message
                        data['acctmgr'] = getattr(e, 'acctmgr', '')
                else:
                    data['registration_error'] = _("""The password store
                                                   does not support
                                                   creating users.""")
            elif req.args.get('remove'):
                sel = req.args.get('sel')
                if sel is None:
                    # so nothing to be done
                    pass
                elif delete_enabled:
                    sel = isinstance(sel, list) and sel or [sel]
                    for account in sel:
                        mgr.delete_user(account)
                else:
                    data['deletion_error'] = _("""The password store does
                                               not support deleting users.""")
            elif req.args.get('change'):
                if password_change_enabled:
                    try:
                        user = req.args.get('change_user')
                        acctmgr = { 'change_username' : user,
                        }
                        error = TracError('')
                        error.acctmgr = acctmgr
                        if not user:
                            error.message = _("Username cannot be empty.")
                            raise error

                        password = req.args.get('change_password')
                        if not password:
                            error.message = _("Password cannot be empty.")
                            raise error

                        if password != req.args.get('change_password_confirm'):
                            error.message = _("The passwords must match.")
                            raise error

                        mgr.set_password(user, password)
                    except TracError, e:
                        data['password_change_error'] = e.message
                        data['acctmgr'] = getattr(e, 'acctmgr', '')
                else:
                    data['password_change_error'] = _("""The password store
                                                      does not support
                                                      changing passwords.""")

        if listing_enabled:
            accounts = {}
            for username in mgr.get_users():
                accounts[username] = {'username': username}
                if guard.user_locked(username):
                    accounts[username]['locked'] = True
                    url = req.href.admin('accounts', 'details', user=username)
                    accounts[username]['review_url'] = url
                    t_lock = guard.lock_time(username)
                    if t_lock > 0:
                        t_release = guard.pretty_release_time(req, username)
                        accounts[username]['release_hint'] = _(
                            "Locked until %(t_release)s",
                            t_release=t_release)

            for username, name, email in self.env.get_known_users():
                account = accounts.get(username)
                if account:
                    account['name'] = name
                    account['email'] = email

            cursor = mgr.last_seen()
            for username, last_visit in cursor:
                account = accounts.get(username)
                if account and last_visit:
                    account['last_visit'] = format_datetime(last_visit, 
                                                            tzinfo=req.tz)
            data['accounts'] = sorted(accounts.itervalues(),
                                      key=lambda acct: acct['username'])
        add_stylesheet(req, 'acct_mgr/acct_mgr.css')
        return 'admin_users.html', data

    # ITemplateProvider methods

    def get_htdocs_dirs(self):
        """Return the absolute path of a directory containing additional
        static resources (such as images, style sheets, etc).
        """
        return [('acct_mgr', resource_filename(__name__, 'htdocs'))]

    def get_templates_dirs(self):
        """Return the absolute path of the directory containing the provided
        Genshi templates.
        """
        return [resource_filename(__name__, 'templates')]


class AccountGuardAdminPage(AccountManagerAdminPage):

    # IAdminPanelProvider
    def get_admin_panels(self, req):
        if req.perm.has_permission('ACCTMGR_USER_ADMIN'):
            yield ('accounts', _("Accounts"), 'details', _("Account details"))

    def render_admin_panel(self, req, cat, page, path_info):
        if page == 'details':
            return self._do_acct_details(req)

    def _do_acct_details(self, req):
        user = req.args.get('user')
        if not user:
            # Accessing user account details directly is not useful,
            # so we revert such request immediately. 
            add_warning(req, Markup(tag.span(tag_(
                "Please choose account by username from list to proceed."
                ))))
            req.redirect(req.href.admin('accounts', 'users'))

        mgr = self.account_manager
        guard = self.account_guard

        if req.method == 'POST':
            if req.args.get('update'):
                req.redirect(req.href.admin('accounts', 'details', user=user))

            if req.args.get('delete') or req.args.get('release'):
                # delete failed login attempts, evaluating attempts count
                if guard.failed_count(user, reset=True) > 0:
                    add_notice(req, Markup(tag.span(tag_(
                        "Failed login attempts for user %(user)s deleted",
                        user=tag.b(user)
                        ))))
            req.redirect(req.href.admin('accounts', 'users'))

        data = {'user': user,}
        stores = StoreOrder(stores=mgr.stores, list=mgr.password_store)
        user_store = mgr.find_user_store(user)
        if not user_store is None:
            data['user_store'] = user_store.__class__.__name__
            data['store_order_num'] = stores[user_store]
        data['ignore_auth_case'] = \
            self.config.getbool('trac', 'ignore_auth_case')

        for username, name, email in self.env.get_known_users():
            if username == user:
                data['name'] = name
                if email:
                    data['email'] = email
                break
        ts_seen = None
        for row in mgr.last_seen(user):
            if row[0] == user and row[1]:
                data['last_visit'] = format_datetime(row[1], tzinfo=req.tz)
                break

        attempts = []
        attempts_count = guard.failed_count(user, reset = None)
        if attempts_count > 0:
            for attempt in guard.get_failed_log(user):
                t = format_datetime(to_datetime(
                                         attempt['time']), tzinfo=req.tz)
                attempts.append({'ipnr': attempt['ipnr'], 'time': t})
        data['attempts'] = attempts
        data['attempts_count'] = attempts_count
        data['pretty_lock_time'] = guard.pretty_lock_time(user, next=True)
        data['lock_count'] = guard.lock_count(user)
        if guard.user_locked(user) is True:
            data['user_locked'] = True
            data['release_time'] = guard.pretty_release_time(req, user)

        if self.env.is_component_enabled(EmailVerificationModule) and \
                mgr.verify_email is True:
            data['verification'] = 'enabled'
            data['email_verified'] = mgr.email_verified(user, email)
            self.log.debug('AcctMgr:admin:_do_acct_details for user \"' + \
                user + '\", email \"' + str(email) + '\": ' + \
                str(data['email_verified']))

        add_stylesheet(req, 'acct_mgr/acct_mgr.css')
        #req.href.admin('accounts', 'details', user=user)
        return 'account_details.html', data

