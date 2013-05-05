# -*- coding: utf-8 -*-
#
# Copyright (C) 2012,2013 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

import re

from trac.core import TracError
from trac.db.api import DatabaseManager
from trac.util.text import to_unicode

from acct_mgr.api import GenericUserIdChanger
from acct_mgr.compat import as_int, exception_to_unicode
from acct_mgr.hashlib_compat import md5


_USER_KEYS = {
    'auth_cookie': 'name',
    'permission': 'username',
    }


def _db_exc(env):
    """Return an object (typically a module) containing all the
    backend-specific exception types as attributes, named
    according to the Python Database API
    (http://www.python.org/dev/peps/pep-0249/).

    This is derived from code found in trac.env.Environment.db_exc (Trac 1.0).
    """
    try:
        module = DatabaseManager(env).get_exceptions()
    except AttributeError:
        module = None
        if dburi.startswith('sqlite:'):
            try:
                import pysqlite2.dbapi2 as sqlite
                module = sqlite
            except ImportError:
                try:
                    import sqlite3 as sqlite
                    module = sqlite
                except ImportError:
                    pass
        elif dburi.startswith('postgres:'):
            try:
                import psycopg2 as psycopg
                module = psycopg
            except ImportError:
                pass
        elif dburi.startswith('mysql:'):
            try:
                import MySQLdb
                module = MySQLdb
            except ImportError:
                pass
        # Do not need more alternatives, because otherwise we wont get here.
    return module

def _get_cc_list(cc_value):
    """Parse cc list.

    Derived from from trac.ticket.model._fixup_cc_list (Trac-1.0).
    """
    cclist = []
    for cc in re.split(r'[;,\s]+', cc_value):
        if cc and cc not in cclist:
            cclist.append(cc)
    return cclist

def _get_db_exc(env):
    return (_db_exc(env).InternalError, _db_exc(env).OperationalError,
            _db_exc(env).ProgrammingError)


class PrimitiveUserIdChanger(GenericUserIdChanger):
    """Handle the simple owner-column replacement case."""

    abstract = True

    column = 'author'
    table = None

    # IUserIdChanger method
    def replace(self, old_uid, new_uid, db):
        result = 0

        cursor = db.cursor()
        try:
            cursor.execute("SELECT COUNT(*) FROM %s WHERE %s=%%s"
                           % (self.table, self.column), (old_uid,))
            exists = cursor.fetchone()
            if exists[0]:
                cursor.execute("UPDATE %s SET %s=%%s WHERE %s=%%s"
                               % (self.table, self.column, self.column),
                               (new_uid, old_uid))
                result = int(exists[0])
                self.log.debug(self.msg(old_uid, new_uid, self.table,
                               self.column, result='%s time(s)' % result))
        except (_get_db_exc(self.env)), e:
            result = exception_to_unicode(e)
            self.log.debug(self.msg(old_uid, new_uid, self.table,
                           self.column, result='failed: %s'
                           % exception_to_unicode(e, traceback=True)))
            return dict(error={(self.table, self.column, None): result})
        return {(self.table, self.column, None): result}


class UniqueUserIdChanger(PrimitiveUserIdChanger):
    """Handle columns, where user IDs are an unique key or part of it."""

    abstract = True

    column = 'sid'

    # IUserIdChanger method
    def replace(self, old_uid, new_uid, db):
        cursor = db.cursor()
        try:
            cursor.execute("DELETE FROM %s WHERE %s=%%s"
                           % (self.table, self.column), (new_uid,))
        except (_get_db_exc(self.env)), e:
            result = exception_to_unicode(e)
            self.log.debug(self.msg(old_uid, new_uid, self.table,
                           self.column, result='failed: %s'
                           % exception_to_unicode(e, traceback=True)))
            return dict(error={(self.table, self.column, None): result})
        return super(UniqueUserIdChanger,
                     self).replace(old_uid, new_uid, db)


class AttachmentUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs in attachments."""

    table = 'attachment'


class AuthCookieUserIdChanger(UniqueUserIdChanger):
    """Change user IDs for authentication cookies."""

    column = 'name'
    table = 'auth_cookie'


class ComponentUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs in components."""

    column = 'owner'
    table = 'component'


class PermissionUserIdChanger(UniqueUserIdChanger):
    """Change user IDs for permissions."""

    column = 'username'
    table = 'permission'


class ReportUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs in reports."""

    table = 'report'


class RevisionUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs in changesets."""

    table = 'revision'


class TicketUserIdChanger(PrimitiveUserIdChanger):
    """Change all user IDs in tickets."""

    table = 'ticket'

    # IUserIdChanger method
    def replace(self, old_uid, new_uid, db):
        results=dict()

        self.column = 'owner'
        result = super(TicketUserIdChanger,
                       self).replace(old_uid, new_uid, db)
        if 'error' in result:
            return result
        results.update(result)

        self.column = 'reporter'
        result = super(TicketUserIdChanger,
                       self).replace(old_uid, new_uid, db)
        if 'error' in result:
            return result
        results.update(result)

        # Replace user ID in Cc ticket column.
        cursor = db.cursor()
        cursor.execute("SELECT id,cc FROM ticket WHERE cc %s" % db.like(),
                       ('%' + db.like_escape(old_uid) + '%',))
        result = 0
        for row in cursor.fetchall():
            cc = _get_cc_list(row[1])
            for i in [i for i,r in enumerate(cc) if r == old_uid]:
                cc[i] = new_uid
                try:
                    cursor.execute("UPDATE ticket SET cc=%s WHERE id=%s",
                                   (', '.join(cc), int(row[0])))
                    result += 1
                except (_get_db_exc(self.env)), e:
                    result = exception_to_unicode(e)
                    self.log.debug(self.msg(old_uid, new_uid, self.table, 'cc',
                                   result='failed: %s'
                                   % exception_to_unicode(e, traceback=True)))
                    return dict(error={(self.table, 'cc', None): result})
        self.log.debug(self.msg(old_uid, new_uid, self.table, 'cc',
                                result='%s time(s)' % result))
        results.update({(self.table, 'cc', None): result})

        table = 'ticket_change'
        self.column = 'author'
        self.table = table
        result = super(TicketUserIdChanger,
                       self).replace(old_uid, new_uid, db)
        if 'error' in result:
            return result
        results.update(result)

        constraint = "field='owner'|'reporter'"
        cursor = db.cursor()
        for column in ('oldvalue', 'newvalue'):
            cursor.execute("""
                SELECT COUNT(*)
                  FROM %s
                 WHERE %s=%%s
                   AND (field='owner'
                        OR field='reporter')
            """ % (table, column), (old_uid,))
            exists = cursor.fetchone()
            result = int(exists[0])
            if exists[0]:
                try:
                    cursor.execute("""
                        UPDATE %s
                           SET %s=%%s
                         WHERE %s=%%s
                           AND (field='owner'
                                OR field='reporter')
                    """ % (table, column, column), (new_uid, old_uid))
                except (_get_db_exc(self.env)), e:
                    result = exception_to_unicode(e)
                    self.log.debug(
                        self.msg(old_uid, new_uid, table, column,
                                 constraint, result='failed: %s'
                                 % exception_to_unicode(e, traceback=True)))
                    return dict(error={(self.table, column,
                                        constraint): result})
            self.log.debug(self.msg(old_uid, new_uid, table, column,
                                    constraint, result='%s time(s)' % result))
            results.update({(table, column, constraint): result})

        # Replace user ID in Cc ticket field changes too.
        constraint = "field='cc'"
        for column in ('oldvalue', 'newvalue'):
            cursor.execute("""
                SELECT ticket,time,%s
                  FROM %s
                 WHERE field='cc'
                   AND %s %s
            """ % (column, table, column, db.like()),
                ('%' + db.like_escape(old_uid) + '%',))

            result = 0
            for row in cursor.fetchall():
                cc = _get_cc_list(row[2])
                for i in [i for i,r in enumerate(cc) if r == old_uid]:
                    cc[i] = new_uid
                    try:
                        cursor.execute("""
                            UPDATE %s
                               SET %s=%%s
                             WHERE ticket=%%s
                               AND time=%%s
                        """ % (table, column),
                            (', '.join(cc), int(row[0]), int(row[1])))
                        result += 1
                    except (_get_db_exc(self.env)), e:
                        result = exception_to_unicode(e)
                        self.log.debug(
                            self.msg(old_uid, new_uid, table, column,
                                     constraint, result='failed: %s'
                                     % exception_to_unicode(e, traceback=True)
                        ))
                        return dict(error={(self.table, column,
                                            constraint): result})
            self.log.debug(self.msg(old_uid, new_uid, table, column,
                                    constraint, result='%s time(s)' % result))
            results.update({(table, column, constraint): result})
        return results


class WikiUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs in wiki pages."""

    table = 'wiki'


# Public functions

def email_associated(env, email, db=None):
    """Returns whether an authenticated user account with that email address
    exists.
    """
    db = _get_db(env, db)
    cursor = db.cursor()
    cursor.execute("""
        SELECT value
          FROM session_attribute
         WHERE authenticated=1 AND name='email' AND value=%s
        """, (email,))
    for row in cursor:
        return True
    return False

def email_verified(env, user, email, db=None):
    """Returns whether the account and email has been verified.

    Use with care, as it returns the private token string,
    if verification is pending.
    """
    if not user_known(env, user) or not email:
        # Nothing more to check here.
        return None
    db = _get_db(env, db)
    cursor = db.cursor()
    cursor.execute("""
        SELECT value
          FROM session_attribute
         WHERE sid=%s AND name='email_verification_sent_to'
        """, (user,))
    for row in cursor:
        env.log.debug('AcctMgr:model:email_verified for user \"' + \
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
        env.log.debug('AcctMgr:model:email_verified for user \"' + \
            user + '\", email \"' + str(email) + '\": ' + str(row[0]))
        return row[0]
    return True

def user_known(env, user, db=None):
    """Returns whether the user has ever been authenticated before."""
    db = _get_db(env, db)
    cursor = db.cursor()
    cursor.execute("""
        SELECT 1
          FROM session
         WHERE authenticated=1 AND sid=%s
        """, (user,))
    for row in cursor:
        return True
    return False


# Utility functions

def change_uid(env, old_uid, new_uid, changers, attr_overwrite):
    """Handle user ID transition for all supported Trac realms."""
    db = _get_db(env)
    # Handle the single unique Trac user ID reference first.
    cursor = db.cursor()
    sql = """
        DELETE
          FROM session
         WHERE authenticated=1 AND sid=%s
        """
    cursor.execute(sql, (new_uid,))
    cursor.execute("""
        INSERT INTO session
                (sid,authenticated,last_visit)
        VALUES  (%s,1,(SELECT last_visit FROM session WHERE sid=%s))
        """, (new_uid, old_uid))
    # Process related attributes.
    attr_count = copy_user_attributes(env, old_uid, new_uid, attr_overwrite,
                                      db=db)
    # May want to keep attributes, if not copied completely.
    if attr_overwrite:
        del_user_attribute(env, old_uid, db=db)

    results = dict()
    results.update({('session_attribute', 'sid', None): attr_count})
    for changer in changers:
        result = changer.replace(old_uid, new_uid, db)
        if 'error' in result:
            # Explicit transaction termination is required here to do clean-up
            # before leaving this context.
            db.rollback()
            db = _get_db(env)
            cursor = db.cursor()
            cursor.execute(sql, (new_uid,))
            return result
        results.update(result)
    # Finally delete old user ID reference after moving everything else.
    cursor.execute(sql, (old_uid,))
    results.update({('session', 'sid', None): 1})
    db.commit()
    return results

def copy_user_attributes(env, username, new_uid, overwrite, db=None):
    """Duplicate attributes for another user, optionally preserving existing
    values.

    Returns the number of changed attributes.
    """
    count = 0
    db = _get_db(env, db)
    attrs = get_user_attribute(env, username, db=db)

    if attrs and username in attrs and attrs[username].get(1):
        attrs_new = get_user_attribute(env, new_uid, db=db)
        if not (attrs_new and new_uid in attrs_new and \
                attrs_new[new_uid].get(1)):
            # No attributes found.
            attrs_new = None
        # Remove value id hashes.
        attrs[username][1].pop('id')
        cursor = db.cursor()
        for attribute, value in attrs[username][1].iteritems():
            if not (attrs_new and attribute in attrs_new[new_uid][1]):
                cursor.execute("""
                    INSERT INTO session_attribute
                            (sid,authenticated,name,value)
                    VALUES  (%s,1,%s,%s)
                    """, (new_uid, attribute, value))
                count += 1
            elif overwrite:
                cursor.execute("""
                    UPDATE session_attribute
                       SET value=%s
                     WHERE sid=%s
                       AND authenticated=1
                       AND name=%s
                    """, (value, new_uid, attribute))
                count += 1
    return count

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
        constraints.append(as_int(authenticated, 0, min=0, max=1))
    if attribute is not None:
        columns.append('name')
        constraints.append(attribute)
    if value is not None:
        columns.append('value')
        constraints.append(to_unicode(value))
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

def prime_auth_session(env, username, db=None):
    """Prime session for registered users before initial login.

    These days there's no distinct user object in Trac, but users consist
    in terms of anonymous or authenticated sessions and related session
    attributes.  So INSERT new sid, needed as foreign key in some db schemata
    later on, at least for PostgreSQL.
    """
    db = _get_db(env, db)
    cursor = db.cursor()
    cursor.execute("""
        SELECT COUNT(*)
          FROM session
         WHERE sid=%s
        """, (username,))
    exists = cursor.fetchone()
    if not exists[0]:
        cursor.execute("""
            INSERT INTO session
                    (sid,authenticated,last_visit)
            VALUES  (%s,1,0)
            """, (username,))
        db.commit()

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
        constraints.append(as_int(authenticated, 0, min=0, max=1))
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

def delete_user(env, user, db=None):
    # Delete session attributes, session and any custom permissions
    # set for the user.
    db = _get_db(env, db)
    cursor = db.cursor()
    for table in ['auth_cookie', 'session_attribute', 'session', 'permission']:
        # Preseed, since variable table and column names aren't allowed
        # as SQL arguments (security measure agains SQL injections).
        sql = """
            DELETE
              FROM %s
             WHERE %s=%%s
            """ % (table, _USER_KEYS.get(table, 'sid'))
        cursor.execute(sql, (user,))
    db.commit()
    # DEVEL: Is this really needed?
    db.close()
    env.log.debug("Purged session data and permissions for user '%s'" % user)

def last_seen(env, user=None, db=None):
    db = _get_db(env, db)
    cursor = db.cursor()
    sql = """
        SELECT sid,last_visit
          FROM session
         WHERE authenticated=1
        """
    if user:
        sql += " AND sid=%s"
        cursor.execute(sql, (user,))
    else:
        cursor.execute(sql)
    # Don't pass over the cursor (outside of scope), only it's content.
    return [row for row in cursor]


# Internal functions

def _get_db(env, db=None):
    return db or env.get_db_cnx()
