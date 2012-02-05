# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2011 Steffen Hoffmann <hoff.st@web.de>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

from pkg_resources  import resource_filename

from trac.config    import  BoolOption, Configuration, ExtensionOption, \
                    Option, OrderedExtensionsOption
from trac.core      import *

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

from acct_mgr.hashlib_compat  import md5


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

    def has_email(self, address):
        """Returns whether a user account with that email address exists.
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

    def has_email(self, email):
        """Returns whether a user account with that email address exists.

        Check db directly - email addresses are not backend-specific.
        """
        exists = False
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("""
            SELECT value
              FROM session_attribute
             WHERE authenticated=1 AND name='email' AND value=%s
            """, (email,))
        for row in cursor:
            exists = True
            break
        return exists

    def email_verified(self, user, email):
        """Returns whether the account and email has been verified.

        Use with care, as it returns the private token string,
        if verification is pending.
        """
        if (self.user_known(user) is False or
               email is None) or email == '':
            # nothing to check here
            return None
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("""
            SELECT value
              FROM session_attribute
             WHERE sid=%s AND name='email_verification_sent_to'
            """, (user,))
        for row in cursor:
            self.log.debug('AcctMgr:api:email_verify for user \"' + \
                user + '\", email \"' + str(email) + '\": ' + str(row[0]))
            if row[0] != email:
                # verification has been sent to different email address
                return None
        cursor.execute("""
            SELECT value
              FROM session_attribute
             WHERE sid=%s AND name='email_verification_token'
            """, (user,))
        for row in cursor:
            # verification token still unverified
            self.log.debug('AcctMgr:api:email_verify for user \"' + \
                user + '\", email \"' + str(email) + '\": ' + str(row[0]))
            return row[0]
        return True

    def user_known(self, user):
        """Returns whether the user has ever been authenticated before.
        """
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("""
            SELECT *
              FROM session
             WHERE authenticated=1 AND sid=%s
            """, (user,))
        for row in cursor:
            return True
        return False

    def last_seen(self, user = None):
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        sql = """
            SELECT sid,last_visit
              FROM session
             WHERE authenticated=1
            """
        if user:
            sql = "%s AND sid='%s'" % (sql, user)
        cursor.execute(sql)
        # Don't pass over the cursor (outside of scope), only it's content.
        res = []
        for row in cursor:
            res.append(row)
        return not len(res) == 0 and res or None

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
        getattr(store, 'delete_user', lambda x: None)(user)
        # Delete session attributes, session and any custom permissions
        # set for the user.
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        for table in ['session_attribute', 'session', 'permission']:
            key = (table == 'permission') and 'username' or 'sid'
            # Preseed, since variable table and column names aren't allowed
            # as SQL arguments (security measure agains SQL injections).
            sql = """
                DELETE
                FROM   %s
                WHERE  %s=%%s
                """ % (table, key)
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


def get_user_attribute(env, username=None, authenticated=1, attribute=None,
                       value=None, db=None):
    """Return user attributes."""
    ALL_COLS = ('sid', 'authenticated', 'name', 'value')
    columns = []
    constraints = []
    if username is not None:
        columns.append('sid')
        constraints.append(username)
    if authenticated is not None:
        columns.append('authenticated')
        constraints.append(authenticated)
    if attribute is not None:
        columns.append('name')
        constraints.append(attribute)
    if value is not None:
        columns.append('value')
        constraints.append(value)
    sel_columns = [col for col in ALL_COLS if col not in columns]
    if len(sel_columns) == 0:
        # No variable left, so only COUNTing is as a sensible task here. 
        sel_stmt = 'COUNT(*)'
    else:
        if 'sid' not in sel_columns:
            sel_columns.append('sid')
        sel_stmt = ','.join(sel_columns)
    if len(columns) > 0:
        where_stmt = ''.join(['WHERE ', '=%s AND '.join(columns), '=%s'])
    else:
        where_stmt = ''
    sql = """
        SELECT  %s
          FROM  session_attribute
        %s
        """ % (sel_stmt, where_stmt)
    sql_args = tuple(constraints)

    db = _get_db(env, db)
    cursor = db.cursor()
    cursor.execute(sql, sql_args)
    rows = cursor.fetchall()
    if rows is None:
        return {}
    res = {}
    for row in rows:
        if sel_stmt == 'COUNT(*)':
            return [row[0]]
        res_row = {}
        res_row.update(zip(sel_columns, row))
        # Merge with constraints, that are constants for this SQL query.
        res_row.update(zip(columns, constraints))
        account = res_row.pop('sid')
        authenticated = res_row.pop('authenticated')
        # Create single unique attribute ID.
        m = md5()
        m.update(''.join([account, str(authenticated),
                           res_row.get('name')]).encode('utf-8'))
        row_id = m.hexdigest()
        if account in res:
            if authenticated in res[account]:
                res[account][authenticated].update({
                    res_row['name']: res_row['value']
                })
                res[account][authenticated]['id'].update({
                    res_row['name']: row_id
                })
            else:
                res[account][authenticated] = {
                    res_row['name']: res_row['value'],
                    'id': {res_row['name']: row_id}
                }
                # Create account ID for additional authentication state.
                m = md5()
                m.update(''.join([account,
                                  str(authenticated)]).encode('utf-8'))
                res[account]['id'][authenticated] = m.hexdigest()
        else:
            # Create account ID for authentication state.
            m = md5()
            m.update(''.join([account, str(authenticated)]).encode('utf-8'))
            res[account] = {authenticated: {res_row['name']: res_row['value'],
                                            'id': {res_row['name']: row_id}},
                            'id': {authenticated: m.hexdigest()}}
    return res

def set_user_attribute(env, username, attribute, value, db=None):
    """Set or update a Trac user attribute within an atomic db transaction."""
    db = _get_db(env, db)
    cursor = db.cursor()
    sql = """
        WHERE   sid=%s
            AND authenticated=1
            AND name=%s
        """
    cursor.execute("""
        UPDATE  session_attribute
            SET value=%s
        """ + sql, (value, username, attribute))
    cursor.execute("""
        SELECT  value
          FROM  session_attribute
        """ + sql, (username, attribute))
    if cursor.fetchone() is None:
        cursor.execute("""
            INSERT INTO session_attribute
                    (sid,authenticated,name,value)
            VALUES  (%s,1,%s,%s)
            """, (username, attribute, value))
    db.commit()

def del_user_attribute(env, username=None, authenticated=1, attribute=None,
                       db=None):
    """Delete one or more Trac user attributes for one or more users."""
    columns = []
    constraints = []
    if username is not None:
        columns.append('sid')
        constraints.append(username)
    if authenticated is not None:
        columns.append('authenticated')
        constraints.append(authenticated)
    if attribute is not None:
        columns.append('name')
        constraints.append(attribute)
    if len(columns) > 0:
        where_stmt = ''.join(['WHERE ', '=%s AND '.join(columns), '=%s'])
    else:
        where_stmt = ''
    sql = """
        DELETE
        FROM    session_attribute
        %s
        """ % where_stmt
    sql_args = tuple(constraints)

    db = _get_db(env, db)
    cursor = db.cursor()
    cursor.execute(sql, sql_args)
    db.commit()

def _get_db(env, db=None):
    return db or env.get_db_cnx()

