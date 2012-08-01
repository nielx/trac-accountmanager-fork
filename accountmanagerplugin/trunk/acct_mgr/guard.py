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
from acct_mgr.model     import del_user_attribute, get_user_attribute, \
                               set_user_attribute


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

        # Adjust related value to promote sane configurations, because the
        # combination of some default values is not meaningful.
        if not self.login_attempt_max_count > 0 and \
                self.user_lock_max_time != 0:
            self.config.set('account-manager', 'user_lock_max_time', '0')
            # Write change back to file to make it permanent.
            self.config.save()

    def failed_count(self, user, ipnr=None, reset=False):
        """Report number of previously logged failed login attempts.

        Enforce login policy with regards to tracking of login attempts
        and user account lock behavior.
        Default `False` for reset value causes logging of another attempt.
        `None` value for reset just reads failed login attempts count.
        `True` value for reset triggers final log deletion.
        """
        value = get_user_attribute(self.env, user, 1, 'failed_logins_count')
        count = value and int(value[user][1].get('failed_logins_count')) or 0
        if reset is None:
            # Report failed attempts count only.
            return count
        if not reset:
            # Trigger the failed attempt logger.
            attempts = self.get_failed_log(user)
            log_length = len(attempts)
            if log_length > self.login_attempt_max_count:
                # Truncate attempts list preserving most recent events.
                del attempts[:(log_length - self.login_attempt_max_count)]
            attempts.append({'ipnr': ipnr,
                             'time': to_utimestamp(to_datetime(None))})
            count += 1
            # Update or create attempts counter and list.
            set_user_attribute(self.env, user, 'failed_logins', str(attempts))
            set_user_attribute(self.env, user, 'failed_logins_count', count)
            self.log.debug("AcctMgr:failed_count(%s): %s" % (user, count))
        else:
            # Delete existing attempts counter and list.
            del_user_attribute(self.env, user, 1, 'failed_logins')
            del_user_attribute(self.env, user, 1, 'failed_logins_count')
            # Delete the lock count too.
            self.lock_count(user, 'reset')
        return count

    def get_failed_log(self, user):
        """Returns an iterable of previously logged failed login attempts.

        The iterable contains a list of dicts in the following form:
        {'ipnr': ipnr, 'time': time_stamp} or an empty list.
        The time stamp format depends on Trac support for POSIX seconds
        (before 0.12) or POSIX microseconds in more recent Trac versions.
        """
        attempts = get_user_attribute(self.env, user, 1, 'failed_logins')
        return attempts and eval(attempts[user][1].get('failed_logins')) or []

    def lock_count(self, user, action='get'):
        """Count, log and report, how often in succession user account
        lock conditions have been met.

        This is the exponent for lock time prolongation calculation too.
        """
        key = 'lock_count'
        if not action == 'reset':
            value = get_user_attribute(self.env, user, 1, key)
            count = value and int(value[user][1].get(key)) or 0
            if not action == 'get':
                # Push and create or update cached count.
                count += 1
                set_user_attribute(self.env, user, key, count)
        else:
            # Reset/delete lock count cache.
            del_user_attribute(self.env, user, 1, key)
            count = 0
        return count

    def lock_time(self, user, next = False):
        """Calculate current time-lock length for user account."""
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
        # Limit maximum lock time.
        t_lock_max = self.user_lock_max_time * 1000000
        if t_lock > t_lock_max:
            t_lock = t_lock_max
        self.log.debug("AcctMgr:lock_time(%s): %s" % (user, t_lock))
        return t_lock

    def pretty_lock_time(self, user, next = False):
        """Convenience method for formatting lock time to string."""
        t_lock = self.lock_time(user, next)
        return (t_lock > 0) and pretty_timedelta(to_datetime(None) - \
            timedelta(microseconds = t_lock)) or None

    def pretty_release_time(self, req, user):
        """Convenience method for formatting lock time to string."""
        ts_release = self.release_time(user)
        if ts_release is None:
            return None
        return format_datetime(to_datetime(
            self.release_time(user)), tzinfo=req.tz)

    def release_time(self, user):
        # Logged attempts required for further checking.
        attempts = self.get_failed_log(user)
        if len(attempts) > 0:
            t_lock = self.lock_time(user)
            if t_lock == 0:
                return None
            return (attempts[-1]['time'] + t_lock)

    def user_locked(self, user):
        """Returns whether the user account is currently locked.

        Expect True, if locked, False, if not and None otherwise.
        """
        if not self.login_attempt_max_count > 0:
            # Account locking turned off by configuration.
            return None
        count = self.failed_count(user, reset=None)
        ts_release = self.release_time(user)
        if count < self.login_attempt_max_count:
            self.log.debug(
                "AcctMgr:user_locked(%s): False (try left)" % user)
            return False
        else:
            if ts_release is None:
                # Account locked permanently.
                self.log.debug(
                    "AcctMgr:user_locked(%s): True (permanently)" % user)
                return True
        # Time-locked or time-lock expired.
        ts_now = to_utimestamp(to_datetime(None))
        self.log.debug(
            "AcctMgr:user_locked(%s): %s" % (user, (ts_release - ts_now > 0)))
        return (ts_release - ts_now > 0)
