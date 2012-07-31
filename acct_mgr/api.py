# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2011,2012 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

from pkg_resources  import resource_filename

from trac.config    import BoolOption, Configuration, ExtensionOption, \
                           Option, OrderedExtensionsOption
from trac.core      import Component, ExtensionPoint, Interface, TracError, \
                           implements

# Import i18n methods.  Fallback modules maintain compatibility to Trac 0.11
# by keeping Babel optional here.
try:
    from  trac.util.translation  import  domain_functions
    add_domain, _, N_, gettext, ngettext, tag_ = \
        domain_functions('acct_mgr', ('add_domain', '_', 'N_', 'gettext',
                                      'ngettext', 'tag_'))
    dgettext = None
except ImportError:
    from  genshi.builder         import  tag as tag_
    from  trac.util.translation  import  gettext
    _ = gettext
    N_ = lambda text: text
    def add_domain(a,b,c=None):
        pass
    def dgettext(domain, string, **kwargs):
        return safefmt(string, kwargs)
    def ngettext(singular, plural, num, **kwargs):
        string = num == 1 and singular or plural
        kwargs.setdefault('num', num)
        return safefmt(string, kwargs)
    def safefmt(string, kwargs):
        if kwargs:
            try:
                return string % kwargs
            except KeyError:
                pass
        return string

_user_keys = {
    'auth_cookie': 'name',
    'permission': 'username',
    }


class IPasswordStore(Interface):
    """An interface for Components that provide a storage method for users and
    passwords.
    """

    def config_key(self):
        """
        '''Deprecated''': new implementations of this interface are not required
        to implement this method, since the prefered way to configure the
        `IPasswordStore` implemenation is by using its class name in
        the `password_store` option.

        Returns a string used to identify this implementation in the config.
        This password storage implementation will be used if the value of
        the config property "account-manager.password_format" matches.
        """

    def get_users(self):
        """Returns an iterable of the known usernames.
        """

    def has_user(self, user):
        """Returns whether the user account exists.
        """

    def set_password(self, user, password, old_password = None):
        """Sets the password for the user.  This should create the user account
        if it doesn't already exist.
        Returns True if a new account was created, False if an existing account
        was updated.
        """

    def check_password(self, user, password):
        """Checks if the password is valid for the user.
    
        Returns True if the correct user and password are specfied.  Returns
        False if the incorrect password was specified.  Returns None if the
        user doesn't exist in this password store.

        Note: Returing `False` is an active rejection of the login attempt.
        Return None to let the auth fall through to the next store in the
        chain.
        """

    def delete_user(self, user):
        """Deletes the user account.
        Returns True if the account existed and was deleted, False otherwise.
        """

class IAccountChangeListener(Interface):
    """An interface for receiving account change events.
    """

    def user_created(self, user, password):
        """New user
        """

    def user_password_changed(self, user, password):
        """Password changed
        """

    def user_deleted(self, user):
        """User deleted
        """

    def user_password_reset(self, user, email, password):
        """User password reset
        """

    def user_email_verification_requested(self, user, token):
        """User verification requested
        """

class AccountManager(Component):
    """The AccountManager component handles all user account management methods
    provided by the IPasswordStore interface.

    The methods will be handled by the underlying password storage
    implementation set in trac.ini with the "account-manager.password_format"
    setting.

    The "account-manager.password_store" may be an ordered list of password
    stores.  If it is a list, then each password store is queried in turn.
    """

    implements(IAccountChangeListener)

    _password_store = OrderedExtensionsOption(
        'account-manager', 'password_store', IPasswordStore,
        include_missing=False)
    _password_format = Option('account-manager', 'password_format')
    stores = ExtensionPoint(IPasswordStore)
    change_listeners = ExtensionPoint(IAccountChangeListener)
    allow_delete_account = BoolOption(
        'account-manager', 'allow_delete_account', True,
        doc="Allow users to delete their own account.")
    force_passwd_change = BoolOption(
        'account-manager', 'force_passwd_change', True,
        doc="Force the user to change password when it's reset.")
    persistent_sessions = BoolOption(
        'account-manager', 'persistent_sessions', False,
        doc="""Allow the user to be remembered across sessions without
            needing to re-authenticate. This is, user checks a
            \"Remember Me\" checkbox and, next time he visits the site,
            he'll be remembered.""")
    refresh_passwd = BoolOption(
        'account-manager', 'refresh_passwd', False,
        doc="""Re-set passwords on successful authentication.
            This is most useful to move users to a new password store or
            enforce new store configuration (i.e. changed hash type),
            but should be disabled/unset otherwise.""")
    verify_email = BoolOption(
        'account-manager', 'verify_email', True,
        doc="Verify the email address of Trac users.")
    username_char_blacklist = Option(
        'account-manager', 'username_char_blacklist', ':[]',
        doc="""Always exclude some special characters from usernames.
            This is enforced upon new user registration.""")

    def __init__(self):
        # bind the 'acct_mgr' catalog to the specified locale directory
        locale_dir = resource_filename(__name__, 'locale')
        add_domain(self.env.path, locale_dir)

    # Public API

    def get_users(self):
        """Get usernames from all active stores.

        Because we allow concurrent active stores, and some stores even don't
        warrant uniqueness within itself, multiple usernames should be
        expected.
        """
        users = []
        for store in self._password_store:
            users.extend(store.get_users())
        return users

    def has_user(self, user):
        exists = False
        user = self.handle_username_casing(user)
        for store in self._password_store:
            if store.has_user(user):
                exists = True
                break
            continue
        return exists

    def set_password(self, user, password, old_password = None):
        user = self.handle_username_casing(user)
        store = self.find_user_store(user)
        if store and not hasattr(store, 'set_password'):
            raise TracError(_(
                """The authentication backend for user %s does not support
                setting the password.
                """ % user))
        elif not store:
            store = self.get_supporting_store('set_password')
        if store:
            if store.set_password(user, password, old_password):
                self._notify('created', user, password)
            else:
                self._notify('password_changed', user, password)
        else:
            raise TracError(_(
                """None of the IPasswordStore components listed in the
                trac.ini supports setting the password or creating users.
                """))

    def check_password(self, user, password):
        valid = False
        user = self.handle_username_casing(user)
        for store in self._password_store:
            valid = store.check_password(user, password)
            if valid:
                if valid == True and (self.refresh_passwd == True) and \
                        self.get_supporting_store('set_password'):
                    self._maybe_update_hash(user, password)
                break
        return valid

    def delete_user(self, user):
        user = self.handle_username_casing(user)
        # Delete from password store 
        store = self.find_user_store(user)
        del_method = getattr(store, 'delete_user', None)
        if callable(del_method):
            del_method(user)
        # Delete session attributes, session and any custom permissions
        # set for the user.
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        for table in ['auth_cookie', 'session_attribute', 'session',
                      'permission']:
            # Preseed, since variable table and column names aren't allowed
            # as SQL arguments (security measure agains SQL injections).
            sql = """
                DELETE
                FROM   %s
                WHERE  %s=%%s
                """ % (table, _user_keys.get(table, 'sid'))
            cursor.execute(sql, (user,))
        db.commit()
        db.close()
        self.log.debug('deleted user: %s' % user)
        self._notify('deleted', user)

    def supports(self, operation):
        try:
            stores = self.password_store
        except AttributeError:
            return False
        else:
            if self.get_supporting_store(operation):
                return True
            else:
                return False

    def password_store(self):
        try:
            return self._password_store
        except AttributeError:
            # fall back on old "password_format" option
            fmt = self._password_format
            for store in self.stores:
                config_key = getattr(store, 'config_key', None)
                if config_key is None:
                    continue
                if config_key() == fmt:
                    return [store]
            # if the "password_format" is not set re-raise the AttributeError
            raise

    password_store = property(password_store)

    def get_supporting_store(self, operation):
        """Returns the IPasswordStore that implements the specified operation.

        None is returned if no supporting store can be found.
        """
        supports = False
        for store in self.password_store:
            if hasattr(store, operation):
                supports = True
                break
            continue
        store = supports and store or None
        return store

    def get_all_supporting_stores(self, operation):
        """Returns a list of stores that implement the specified operation"""
        stores = []
        for store in self.password_store:
            if hasattr(store, operation):
                stores.append(store)
            continue
        return stores

    def find_user_store(self, user):
        """Locates which store contains the user specified.

        If the user isn't found in any IPasswordStore in the chain, None is
        returned.
        """
        ignore_auth_case = self.config.getbool('trac', 'ignore_auth_case')
        user_stores = []
        for store in self._password_store:
            userlist = store.get_users()
            user_stores.append((store, userlist))
            continue
        user = self.handle_username_casing(user)
        for store in user_stores:
            if user in store[1]:
                return store[0]
            continue
        return None

    def handle_username_casing(self, user):
        """Enforce lowercase usernames if required.

        Comply with Trac's own behavior, when case-insensitive
        user authentication is set to True.
        """
        ignore_auth_case = self.config.getbool('trac', 'ignore_auth_case')
        return ignore_auth_case and user.lower() or user

    def _maybe_update_hash(self, user, password):
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        sql = """
            SELECT  sid
              FROM  session_attribute
            WHERE   sid=%s
                AND name='password_refreshed'
                AND value='1'
            """
        cursor.execute(sql, (user,))
        if cursor.fetchone() is None:
            self.log.debug('refresh password for user: %s' % user)
            store = self.find_user_store(user)
            pwstore = self.get_supporting_store('set_password')
            if pwstore.set_password(user, password) == True:
                # Account re-created according to current settings
                if store and not (store.delete_user(user) == True):
                    self.log.warn(
                        "failed to remove old entry for user '%s'" % user)
            cursor.execute("""
                UPDATE  session_attribute
                    SET value='1'
                WHERE   sid=%s
                    AND name='password_refreshed'
                """, (user,))
            cursor.execute(sql, (user,))
            if cursor.fetchone() is None:
                cursor.execute("""
                    INSERT INTO session_attribute
                            (sid,authenticated,name,value)
                    VALUES  (%s,1,'password_refreshed',1)
                    """, (user,))
            db.commit()

    def _notify(self, func, *args):
        func = 'user_' + func
        for l in self.change_listeners:
            getattr(l, func)(*args)

    # IAccountChangeListener methods

    def user_created(self, user, password):
        self.log.info('Created new user: %s' % user)

    def user_password_changed(self, user, password):
        self.log.info('Updated password for user: %s' % user)

    def user_deleted(self, user):
        self.log.info('Deleted user: %s' % user)

    def user_password_reset(self, user, email, password):
        self.log.info('Password reset user: %s, %s'%(user, email))
        
    def user_email_verification_requested(self, user, token):
        self.log.info('Email verification requested user: %s' % user)
