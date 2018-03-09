# -*- coding: utf-8 -*-
#
# Copyright (C) 2012-2014 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#

import hashlib
import re

from acct_mgr.api import GenericUserIdChanger
from trac.util import as_int
from trac.util.text import exception_to_unicode, to_unicode

_USER_KEYS = {
    'auth_cookie': 'name',
    'permission': 'username',
}


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
    exc = env.db_exc
    return exc.InternalError, exc.OperationalError, exc.ProgrammingError


class PrimitiveUserIdChanger(GenericUserIdChanger):
    """Handle the simple owner-column replacement case."""

    abstract = True

    column = 'author'
    table = None

    # IUserIdChanger method
    def replace(self, old_uid, new_uid):
        result = 0

        try:
            with self.env.db_transaction as db:
                for count, in db("""
                        SELECT COUNT(*) FROM %s WHERE %s=%%s
                        """ % (self.table, self.column), (old_uid,)):
                    if count:
                        db("UPDATE %s SET %s=%%s WHERE %s=%%s"
                           % (self.table, self.column, self.column),
                           (new_uid, old_uid))
                    result = int(count)
                self.log.debug(self.msg(old_uid, new_uid, self.table,
                                        self.column,
                                        result='%s time(s)' % result))
        except _get_db_exc(self.env), e:
            result = exception_to_unicode(e)
            msg = 'failed: %s' % exception_to_unicode(e, traceback=True)
            self.log.debug(self.msg(old_uid, new_uid, self.table,
                                    self.column, result=msg))
            return dict(error={(self.table, self.column, None): result})
        return {(self.table, self.column, None): result}


class UniqueUserIdChanger(PrimitiveUserIdChanger):
    """Handle columns, where user IDs are an unique key or part of it."""

    abstract = True

    column = 'sid'

    # IUserIdChanger method
    def replace(self, old_uid, new_uid):
        try:
            self.env.db_transaction("""
                DELETE FROM %s WHERE %s=%%s
                """ % (self.table, self.column), (new_uid,))
        except _get_db_exc(self.env), e:
            result = exception_to_unicode(e)
            msg = 'failed: %s' % exception_to_unicode(e, traceback=True)
            self.log.debug(self.msg(old_uid, new_uid, self.table,
                                    self.column, result=msg))
            return dict(error={(self.table, self.column, None): result})
        return super(UniqueUserIdChanger, self).replace(old_uid, new_uid)


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
    def replace(self, old_uid, new_uid):
        results = {}

        with self.env.db_transaction as db:
            self.column = 'owner'
            result = super(TicketUserIdChanger, self).\
                     replace(old_uid, new_uid)
            if 'error' in result:
                return result
            results.update(result)

            self.column = 'reporter'
            result = super(TicketUserIdChanger, self).\
                     replace(old_uid, new_uid)
            if 'error' in result:
                return result
            results.update(result)

            # Replace user ID in Cc ticket column.
            result = 0
            for row in db("""
                    SELECT id,cc FROM ticket WHERE cc %s
                    """ % db.like(), ('%' + db.like_escape(old_uid) + '%',)):
                cc = _get_cc_list(row[1])
                for i in [i for i, r in enumerate(cc) if r == old_uid]:
                    cc[i] = new_uid
                    try:
                        db("UPDATE ticket SET cc=%s WHERE id=%s",
                           (', '.join(cc), int(row[0])))
                        result += 1
                    except _get_db_exc(self.env), e:
                        result = exception_to_unicode(e)
                        msg = 'failed: %s' \
                              % exception_to_unicode(e, traceback=True)
                        self.log.debug(
                            self.msg(old_uid, new_uid, self.table, 'cc',
                                     result=msg))
                        return dict(error={(self.table, 'cc', None): result})
            self.log.debug(self.msg(old_uid, new_uid, self.table, 'cc',
                                    result='%s time(s)' % result))
            results.update({(self.table, 'cc', None): result})

            table = 'ticket_change'
            self.column = 'author'
            self.table = table
            result = super(TicketUserIdChanger,
                           self).replace(old_uid, new_uid)
            if 'error' in result:
                return result
            results.update(result)

            constraint = "field='owner'|'reporter'"
            for column in ('oldvalue', 'newvalue'):
                for count, in db("""
                        SELECT COUNT(*) FROM %s
                        WHERE %s=%%s AND (field='owner' OR field='reporter')
                        """ % (table, column), (old_uid,)):
                    result = int(count)
                if result:
                    try:
                        db("""
                            UPDATE %s SET %s=%%s
                            WHERE %s=%%s AND
                             (field='owner' OR field='reporter')
                            """ % (table, column, column), (new_uid, old_uid))
                    except _get_db_exc(self.env), e:
                        result = exception_to_unicode(e)
                        msg = 'failed: %s' % \
                              exception_to_unicode(e, traceback=True)
                        self.log.debug(
                            self.msg(old_uid, new_uid, table, column,
                                     constraint, result=msg))
                        return dict(error={(self.table, column,
                                            constraint): result})
                self.log.debug(self.msg(old_uid, new_uid, table, column,
                                        constraint,
                                        result='%s time(s)' % result))
                results.update({(table, column, constraint): result})

            # Replace user ID in Cc ticket field changes too.
            constraint = "field='cc'"
            for column in ('oldvalue', 'newvalue'):
                result = 0
                for row in db("""
                        SELECT ticket,time,%s FROM %s
                        WHERE field='cc' AND %s %s
                        """ % (column, table, column, db.like()),
                              ('%' + db.like_escape(old_uid) + '%',)):
                    cc = _get_cc_list(row[2])
                    for i in [i for i, r in enumerate(cc) if r == old_uid]:
                        cc[i] = new_uid
                        try:
                            db("""
                                UPDATE %s SET %s=%%s
                                WHERE ticket=%%s AND time=%%s
                                """ % (table, column),
                               (', '.join(cc), int(row[0]), int(row[1])))
                            result += 1
                        except _get_db_exc(self.env), e:
                            result = exception_to_unicode(e)
                            msg = 'failed: %s' % \
                                  exception_to_unicode(e, traceback=True)
                            self.log.debug(
                                self.msg(old_uid, new_uid, table, column,
                                         constraint, result=msg))
                            return dict(error={(self.table, column,
                                                constraint): result})
                self.log.debug(self.msg(old_uid, new_uid, table, column,
                                        constraint,
                                        result='%s time(s)' % result))
                results.update({(table, column, constraint): result})
        return results


class WikiUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs in wiki pages."""

    table = 'wiki'


# Public functions

def email_associated(env, email):
    """Returns whether an authenticated user account with that email address
    exists.
    """
    for _ in env.db_query("""
            SELECT value FROM session_attribute
            WHERE authenticated=1 AND name='email' AND value=%s
            """, (email,)):
        return True
    return False


def email_verified(env, user, email):
    """Returns whether the account and email has been verified.
    """
    if not user_known(env, user) or not email:
        return None  # Nothing more to check here.

    return email_verification_token(env, user, email) is None


def email_verification_token(env, user, email):
    """Returns the email verification token, or `None` if the email has
    been verified. Returns an empty string if the email verification
    token has been sent to an address different from the one currently
    set in the session preferences.
    """
    with env.db_query as db:
        for row in db("""
                SELECT value
                  FROM session_attribute
                 WHERE sid=%s AND name='email_verification_sent_to'
                """, (user,)):
            env.log.debug('AcctMgr:model:email_verified for user "%s", email '
                          '"%s": %s', user, email, row[0])
            if row[0] != email:
                # verification has been sent to different email address
                return ''

        for row in db("""
                SELECT value
                  FROM session_attribute
                 WHERE sid=%s AND name='email_verification_token'
                """, (user,)):
            env.log.debug('AcctMgr:model:email_verified for user "%s", email '
                          '"%s": %s', user, email, row[0])
            return row[0]


def user_known(env, user):
    """Returns whether the user has ever been authenticated before."""

    for _ in env.db_query("""
            SELECT 1
             FROM session
            WHERE authenticated=1 AND sid=%s
            """, (user,)):
        return True

    return False


# Utility functions

def change_uid(env, old_uid, new_uid, changers, attr_overwrite):
    """Handle user ID transition for all supported Trac realms."""

    with env.db_transaction as db:
        # Handle the single unique Trac user ID reference first.
        db("""
            DELETE FROM session
            WHERE authenticated=1 AND sid=%s
            """, (new_uid,))
        db("""
            INSERT INTO session (sid,authenticated,last_visit)
            VALUES  (%s,1,(SELECT last_visit FROM session WHERE sid=%s))
            """, (new_uid, old_uid))
        # Process related attributes.
        attr_count = _copy_user_attributes(env, old_uid, new_uid,
                                           attr_overwrite)
        # May want to keep attributes, if not copied completely.
        if attr_overwrite:
            del_user_attribute(env, old_uid)

        results = dict()
        results.update({('session_attribute', 'sid', None): attr_count})
        for changer in changers:
            result = changer.replace(old_uid, new_uid)
            if 'error' in result:
                return result
            results.update(result)
        # Finally delete old user ID reference after moving everything else.
        db("""
            DELETE FROM session
            WHERE authenticated=1 AND sid=%s
            """, (old_uid,))
        results.update({('session', 'sid', None): 1})
    if hasattr(env, 'invalidate_known_users_cache'):
        env.invalidate_known_users_cache()

    return results


def _copy_user_attributes(env, username, new_uid, overwrite):
    """Duplicate attributes for another user, optionally preserving existing
    values.

    Returns the number of changed attributes.
    """
    count = 0

    with env.db_transaction as db:
        attrs = get_user_attribute(env, username)

        if attrs and username in attrs and attrs[username].get(1):
            attrs_new = get_user_attribute(env, new_uid)
            if not (attrs_new and new_uid in attrs_new and
                        attrs_new[new_uid].get(1)):
                # No attributes found.
                attrs_new = None
            # Remove value id hashes.
            attrs[username][1].pop('id')
            for attribute, value in attrs[username][1].iteritems():
                if not (attrs_new and attribute in attrs_new[new_uid][1]):
                    db("""
                        INSERT INTO session_attribute
                          (sid,authenticated,name,value)
                        VALUES (%s,1,%s,%s)
                        """, (new_uid, attribute, value))
                    count += 1
                elif overwrite:
                    db("""
                        UPDATE session_attribute SET value=%s
                         WHERE sid=%s
                          AND authenticated=1
                          AND name=%s
                        """, (value, new_uid, attribute))
                    count += 1
    if hasattr(env, 'invalidate_known_users_cache'):
        env.invalidate_known_users_cache()

    return count


def get_user_attribute(env, username=None, authenticated=1, attribute=None,
                       value=None):
    """Return user attributes."""
    all_cols = ('sid', 'authenticated', 'name', 'value')
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
    sel_columns = [col for col in all_cols if col not in columns]
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

    res = {}
    for row in env.db_query(sql, sql_args):
        if sel_stmt == 'COUNT(*)':
            return [row[0]]
        res_row = {}
        res_row.update(zip(sel_columns, row))
        # Merge with constraints, that are constants for this SQL query.
        res_row.update(zip(columns, constraints))
        account = res_row.pop('sid')
        authenticated = res_row.pop('authenticated')
        # Create single unique attribute ID.
        m = hashlib.md5()
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
                m = hashlib.md5()
                m.update(''.join([account,
                                  str(authenticated)]).encode('utf-8'))
                res[account]['id'][authenticated] = m.hexdigest()
        else:
            # Create account ID for authentication state.
            m = hashlib.md5()
            m.update(''.join([account, str(authenticated)]).encode('utf-8'))
            res[account] = {
                authenticated: {
                    res_row['name']: res_row['value'],
                    'id': {res_row['name']: row_id}
                },
                'id': {authenticated: m.hexdigest()}
            }
    return res


def prime_auth_session(env, username):
    """Prime session for registered users before initial login.
    """
    with env.db_transaction as db:
        for count, in db("""
                SELECT COUNT(*) FROM session
                WHERE sid=%s AND authenticated=1
                """, (username,)):
            if not count:
                db("""
                    INSERT INTO session (sid,authenticated,last_visit)
                    VALUES (%s,1,0)
                    """, (username,))
    if hasattr(env, 'invalidate_known_users_cache'):
        env.invalidate_known_users_cache()


def set_user_attribute(env, username, attribute, value):
    """Set or update a Trac user attribute within an atomic db transaction."""

    sql = "WHERE sid=%s AND authenticated=1 AND name=%s"

    with env.db_transaction as db:
        db("""
            UPDATE session_attribute SET value=%s
            """ + sql, (value, username, attribute))
        for _, in db("""
                SELECT value FROM session_attribute
                """ + sql, (username, attribute)):
            break
        else:
            db("""
                INSERT INTO session_attribute (sid,authenticated,name,value)
                VALUES (%s,1,%s,%s)
                """, (username, attribute, value))
    if hasattr(env, 'invalidate_known_users_cache'):
        env.invalidate_known_users_cache()


def del_user_attribute(env, username=None, authenticated=1, attribute=None):
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
    sql = "DELETE FROM session_attribute %s" % where_stmt
    sql_args = tuple(constraints)

    env.db_transaction(sql, sql_args)
    if hasattr(env, 'invalidate_known_users_cache'):
        env.invalidate_known_users_cache()


def delete_user(env, user):
    # Delete session attributes, session and any custom permissions
    # set for the user.
    with env.db_transaction as db:
        for table in ['auth_cookie', 'session_attribute', 'session',
                      'permission']:
            # Pre-seed, since variable table and column names aren't allowed
            # as SQL arguments (security measure against SQL injections).
            sql = """
                    DELETE FROM %s WHERE %s=%%s
                    """ % (table, _USER_KEYS.get(table, 'sid'))
            db(sql, (user,))

    env.log.debug("Purged session data and permissions for user '%s'", user)
    if hasattr(env, 'invalidate_known_users_cache'):
        env.invalidate_known_users_cache()


def last_seen(env, user=None):
    sql = """
        SELECT sid,last_visit
          FROM session
         WHERE authenticated=1
        """
    if user:
        sql += " AND sid=%s"
        return list(env.db_query(sql, (user,)))
    else:
        return list(env.db_query(sql))
