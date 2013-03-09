# -*- coding: utf-8 -*-
#
# Copyright (C) 2012,2013 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

from trac.util.text import to_unicode

from acct_mgr.api import GenericUserIdChanger
from acct_mgr.hashlib_compat import md5
from acct_mgr.util import as_int, exception_to_unicode


_USER_KEYS = {
    'auth_cookie': 'name',
    'permission': 'username',
    }


class PrimitiveUserIdChanger(GenericUserIdChanger):
    """Handle the simple owner-column replacement case."""

    abstract = True

    field = 'author'
    table = None

    # IUserIdChanger method
    def replace(self, old_uid, new_uid, db):
        result = 0
        if not self.table:
            self.table = self.realm

        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM %s WHERE %s=%%s"
                       % (self.table, self.field), (old_uid,))
        exists = cursor.fetchone()
        if exists[0]:
            try:
                cursor.execute("UPDATE %s SET %s=%%s WHERE %s=%%s"
                               % (self.table, self.field, self.field),
                               (new_uid, old_uid))
                result = int(exists[0])
                self.log.debug(self.msg(old_uid, new_uid, self.table,
                               result='%s time(s)' % result))
            except Exception, e:
                result = exception_to_unicode(e)
                self.log.debug(self.msg(old_uid, new_uid, self.table,
                               result='failed: %s' %
                               exception_to_unicode(e, traceback=True)))
        return {'%s %s' % (self.table, self.field): result}


class UniqueUserIdChanger(GenericUserIdChanger):
    """Handle columns, where user IDs are an unique key or part of it."""

    abstract = True

    field = 'sid'
    table = None

    # IUserIdChanger method
    def replace(self, old_uid, new_uid, db):
        result = 0
        if not self.table:
            self.table = self.realm

        cursor = db.cursor()
        cursor.execute("DELETE FROM %s WHERE %s=%%s"
                       % (self.table, self.field), (new_uid,))

        cursor.execute("SELECT COUNT(*) FROM %s WHERE %s=%%s"
                       % (self.table, self.field), (old_uid,))
        exists = cursor.fetchone()
        if exists[0]:
            try:
                cursor.execute("UPDATE %s SET %s=%%s WHERE %s=%%s"
                               % (self.table, self.field, self.field),
                               (new_uid, old_uid))
                result = int(exists[0])
                self.log.debug(self.msg(old_uid, new_uid, self.table,
                               result='%s time(s)' % result))
            except Exception, e:
                result = exception_to_unicode(e)
                self.log.debug(self.msg(old_uid, new_uid, self.table,
                               result='failed: %s' %
                               exception_to_unicode(e, traceback=True)))
        return {'%s %s' % (self.table, self.field): result}


class AttachmentUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs in attachments."""

    realm = 'attachment'


class AuthCookieUserIdChanger(UniqueUserIdChanger):
    """Change user IDs for authentication cookies."""

    field = 'name'
    realm = 'auth_cookie'


class ComponentUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs in components."""

    field = 'owner'
    realm = 'component'


class PermissionUserIdChanger(UniqueUserIdChanger):
    """Change user IDs for permissions."""

    field = 'username'
    realm = 'permission'


class ReportUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs in reports."""

    realm = 'report'


class RevisionUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs in changesets."""

    realm = 'revision'


class SessionAttributesUserIdChanger(UniqueUserIdChanger):
    """Change user IDs for session attributes."""

    realm = 'session_attribute'


class TicketUserIdChanger(PrimitiveUserIdChanger):
    """Change all user IDs in tickets."""

    field = 'owner'
    realm = 'ticket'

    # IUserIdChanger method
    def replace(self, old_uid, new_uid, db):
        results = dict()

        results.update(super(TicketUserIdChanger,
                             self).replace(old_uid, new_uid, db))
        self.field = 'reporter'
        results.update(super(TicketUserIdChanger,
                             self).replace(old_uid, new_uid, db))
        self.field = 'author'
        self.table = 'ticket_change'
        results.update(super(TicketUserIdChanger,
                             self).replace(old_uid, new_uid, db))
        cursor = db.cursor()
        for field in ('oldvalue', 'newvalue'):
            cursor.execute("""
                SELECT COUNT(*)
                  FROM %s
                 WHERE %s=%%s
                   AND (field='owner'
                        OR field='reporter')
            """ % (self.table, field), (old_uid,))
            exists = cursor.fetchone()
            if exists[0]:
                realm = 'ticket_change: %s = owner OR reporter' % field
                result = int(exists[0])
                try:
                    cursor.execute("""
                        UPDATE %s
                           SET %s=%%s
                         WHERE %s=%%s
                           AND (field='owner'
                                OR field='reporter')
                    """ % (self.table, field, field), (new_uid, old_uid))
                    self.log.debug(self.msg(old_uid, new_uid, realm,
                                   result='%s time(s)' % result))
                except Exception, e:
                    result = exception_to_unicode(e)
                    self.log.debug(self.msg(old_uid, new_uid, realm,
                                   realm=realm, result='failed: %s' %
                                   exception_to_unicode(e, traceback=True)))
                results.update({realm: result})
        return results


class WikiUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs in wiki pages."""

    realm = 'wiki'


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

def change_uid(env, old_uid, new_uid, changers):
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
    results = dict()
    for changer in changers:
        results.update(changer.replace(old_uid, new_uid, db))
    # Finally delete old user ID reference after moving everything else.
    cursor.execute(sql, (old_uid,))
    results.update(dict(session=1))
    db.commit()
    return results

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
