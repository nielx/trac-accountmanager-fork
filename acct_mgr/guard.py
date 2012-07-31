# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

from datetime           import timedelta

from trac.config        import Configuration, IntOption, Option
from trac.core          import Component
from trac.util.datefmt  import format_datetime, pretty_timedelta, \
                               to_datetime
try:
    from trac.util.datefmt  import to_utimestamp
except ImportError:
    # Fallback for Trac 0.11 compatibility
    from trac.util.datefmt  import to_timestamp as to_utimestamp

from acct_mgr.api       import AccountManager


class AccountGuard(Component):
    """The AccountGuard component protects against brute-force attacks
    on user passwords.

    It does so by adding logging of failed login attempts,
    account status tracking and administative user account locking.
    Configurable time-locks with exponential lock time prolongation
    allow to balance graceful handling of failed login attempts and
    reasonable protection against attempted brute-force attacks. 
    """

    login_attempt_max_count = IntOption(
        'account-manager', 'login_attempt_max_count', 0,
        doc="""Lock user account after specified number of login attempts.
            Value zero means no limit.""")
    user_lock_time = IntOption(
        'account-manager', 'user_lock_time', '0',
        doc="""Drop user account lock after specified time (seconds).
            Value zero means unlimited lock time.""")
    user_lock_max_time = IntOption(
        'account-manager', 'user_lock_max_time', '86400',
        doc="""Limit user account lock time to specified time (seconds).
            This is relevant only with user_lock_time_progression > 1.""")
    user_lock_time_progression = Option(
        'account-manager', 'user_lock_time_progression', '1',
        doc="""Extend user account lock time incrementally. This is
            based on logarithmic calculation and decimal numbers accepted:
            Value '1' means constant lock time per failed login attempt.
            Value '2' means double locktime after 2nd lock activation,
            four times the initial locktime after 3rd, and so on.""")

    def __init__(self):
        self.mgr = AccountManager(self.env)

        # adjust related value to promote sane configurations
        if not self.login_attempt_max_count > 0:
            self.config.set('account-manager', 'user_lock_max_time', '0')

    def failed_count(self, user, ipnr = None, reset = False):
        """Report number of previously logged failed login attempts.

        Enforce login policy with regards to tracking of login attempts
        and user account lock behavior.
        Default `False` for reset value causes logging of another attempt.
        `None` value for reset just reads failed login attempts count.
        `True` value for reset triggers final log deletion.
        """
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("""
            SELECT value
              FROM session_attribute
             WHERE authenticated=1 AND
                   name='failed_logins_count' AND sid=%s
            """, (user,))
        count = None
        for row in cursor:
            count = eval(row[0])
            break
        if count is None:
            count = 0
        if reset is None:
            # report failed attempts count
            return count

        if reset is not True:
            # failed attempt logger
            attempts = self.get_failed_log(user)
            log_length = len(attempts)
            if log_length > self.login_attempt_max_count:
                # truncate attempts list
                del attempts[:(log_length - self.login_attempt_max_count)]
            attempts.append({'ipnr': ipnr,
                             'time': to_utimestamp(to_datetime(None))})
            count += 1
            # update or create existing attempts list
            for key, value in [('failed_logins', str(attempts)),
                               ('failed_logins_count', count)]:
                sql = """
                    WHERE   authenticated=1
                        AND name=%s
                        AND sid=%s
                    """
                cursor.execute("""
                    UPDATE  session_attribute
                        SET value=%s
                """ + sql, (value, key, user))
                cursor.execute("""
                    SELECT  value
                    FROM    session_attribute
                """ + sql, (key, user))
                if cursor.fetchone() is None:
                    cursor.execute("""
                        INSERT
                        INTO session_attribute
                                 (sid,authenticated,name,value)
                        VALUES   (%s,1,%s,%s)
                    """, (user, key, value))
            db.commit()
            self.log.debug(
                'AcctMgr:failed_count(%s): ' % user + str(count))
            return count
        else:
            # delete existing attempts list
            cursor.execute("""
                DELETE
                FROM   session_attribute
                WHERE  authenticated=1
                    AND (name='failed_logins'
                        OR name='failed_logins_count')
                    AND sid=%s
                """, (user,))
            db.commit()
            # delete lock count too
            self.lock_count(user, 'reset')
            return count

    def get_failed_log(self, user):
        """Returns an iterable of previously logged failed login attempts.

        Iterable content: {'ipnr': ipnr, 'time': posix_microsec_time_stamp}
        """
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("""
            SELECT  value
            FROM    session_attribute
            WHERE   authenticated=1
                AND name='failed_logins'
                AND sid=%s
            """, (user,))
        # read list and add new attempt
        attempts = []
        for row in cursor:
            attempts = eval(row[0])
            break
        return attempts

    def lock_count(self, user, action = 'get'):
        """Count, log and report, how often in succession user account
        lock conditions have been met.

        This is the exponent for lock time prolongation calculation too.
        """
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        if not action == 'reset':
            sql = """
                WHERE   authenticated=1
                    AND name='lock_count'
                    AND sid=%s
                """ 
            cursor.execute("""
                SELECT  value
                FROM    session_attribute
            """ + sql, (user,))
            lock_count = None
            for row in cursor:
                lock_count = eval(row[0])
                break
            if action == 'get':
                return (lock_count or 0)
            else:
                # push and update cached lock_count
                if lock_count is None:
                    # create lock_count cache
                    cursor.execute("""
                        INSERT INTO session_attribute
                                (sid,authenticated,name,value)
                        VALUES  (%s,1,'lock_count',%s)
                        """, (user, 1))
                    lock_count = 1
                else:
                    lock_count += 1
                    cursor.execute("""
                        UPDATE  session_attribute
                            SET value=%s
                        """ + sql, (lock_count, user))
                db.commit()
                return lock_count
        else:
            # reset/delete lock_count cache
            cursor.execute("""
                DELETE
                FROM    session_attribute
                WHERE   authenticated=1
                    AND name='lock_count'
                    AND sid=%s
                """, (user,))
            db.commit()
            return 0

    def lock_time(self, user, next = False):
        """Calculate current time-lock length a user.
        """
        base = float(self.user_lock_time_progression)
        lock_count = self.lock_count(user)
        if not lock_count > 0:
            return 0
        else:
            if next is False:
                exponent = lock_count - 1
            else:
                exponent = lock_count
        t_lock = self.user_lock_time * 1000000 * base ** exponent
        # limit maximum lock time
        t_lock_max = self.user_lock_max_time * 1000000
        if t_lock > t_lock_max:
            t_lock = t_lock_max
        self.log.debug('AcctMgr:lock_time(%s): ' % user + str(t_lock))
        return t_lock

    def pretty_lock_time(self, user, next = False):
        """Convenience method for formatting lock time to string.
        """
        t_lock = self.lock_time(user, next)
        return (t_lock > 0) and pretty_timedelta(to_datetime(None) - \
            timedelta(microseconds = t_lock)) or None

    def pretty_release_time(self, req, user):
        """Convenience method for formatting lock time to string.
        """
        ts_release = self.release_time(user)
        if ts_release is None:
            return None
        return format_datetime(to_datetime(
            self.release_time(user)), tzinfo=req.tz)

    def release_time(self, user):
        # logged attempts required for further checking
        attempts = self.get_failed_log(user)
        if len(attempts) > 0:
            t_lock = self.lock_time(user)
            if t_lock == 0:
                return None
            return (attempts[-1]['time'] + t_lock)

    def user_locked(self, user):
        """Returns whether the user account is currently locked.

        Expect False, if not, and True, if locked.
        """
        if not self.login_attempt_max_count > 0:
            # account locking turned off by configuration
            return None
        count = self.failed_count(user, reset=None)
        ts_release = self.release_time(user)
        if count < self.login_attempt_max_count:
            self.log.debug(
                'AcctMgr:user_locked(%s): False (try left)' % user)
            return False
        else:
            if ts_release is None:
                # permanently locked
                self.log.debug(
                    'AcctMgr:user_locked(%s): True (permanently)' % user)
                return True
        # time-locked or time-lock expired
        self.log.debug(
            'AcctMgr:user_locked(%s): ' % user + \
            str((ts_release - to_utimestamp(to_datetime(None))) > 0))
        return ((ts_release - to_utimestamp(to_datetime(None))) > 0)
