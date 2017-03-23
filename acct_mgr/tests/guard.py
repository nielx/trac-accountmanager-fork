# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

import shutil
import tempfile
import unittest
from Cookie import SimpleCookie as Cookie
from time import sleep

from trac.test import EnvironmentStub, Mock
from trac.util.datefmt import to_datetime, to_timestamp
from trac.web.session import Session

from acct_mgr.guard import AccountGuard


class AccountGuardTestCase(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub(default_data=True,
                                   enable=['trac.*', 'acct_mgr.guard.*'])
        self.env.path = tempfile.mkdtemp()
        self.env.config.set('account-manager', 'login_attempt_max_count', 1)

        self.user = 'user'
        self.session = self._create_session(self.user)
        self.guard = AccountGuard(self.env)

    def tearDown(self):
        self.env.shutdown()
        shutil.rmtree(self.env.path)

    # Helpers

    def _create_session(self, user, authenticated=1, name='', email=''):
        args = dict(username=user, name=name, email=email)
        incookie = Cookie()
        incookie['trac_session'] = '123456'
        req = Mock(authname=bool(authenticated) and user or 'anonymous',
                   args=args, base_path='/',
                   chrome=dict(warnings=list()),
                   href=Mock(prefs=lambda x: None),
                   incookie=incookie, outcookie=Cookie(),
                   redirect=lambda x: None)
        req.session = Session(self.env, req)
        req.session.save()
        return req.session

    def _mock_failed_attempt(self, requests=1):
        ipnr = '127.0.0.1'
        ts = to_timestamp(to_datetime(None))
        attempts = eval(self.session.get('failed_logins', '[]'))
        count = int(self.session.get('failed_logins_count', 0))
        lock_count = int(self.session.get('lock_count', 0))
        max_ = self.env.config.getint('account-manager',
                                     'login_attempt_max_count')
        for r in range(requests):
            attempts.append(dict(ipnr=ipnr, time=ts))
            count += 1
            # Assume, that every lock is enforced.
            if not count < max_:
                lock_count += 1
        self.session['failed_logins'] = str(attempts)
        self.session['failed_logins_count'] = count
        self.session['lock_count'] = lock_count
        self.session.save()
        return ts

    # Tests

    def test_failed_count(self):
        ipnr = '127.0.0.1'

        # Won't track anonymous sessions and unknown accounts/users.
        self.assertEqual(self.guard.failed_count(None, ipnr), 0)

        # Regular account without failed attempts logged.
        user = self.user
        # Start without failed attempts logged, accumulating failed attempts.
        self.assertEqual(self.guard.failed_count(user, ipnr), 1)
        self.assertEqual(self.guard.failed_count(user, ipnr), 2)
        # Read failed attempts.
        self.assertEqual(self.guard.failed_count(user, ipnr, None), 2)
        # Reset failed attempts, returning deleted attemps.
        self.assertEqual(self.guard.failed_count(user, reset=True), 2)
        self.assertEqual(self.guard.failed_count(user, reset=None), 0)

    def test_functional(self):
        ipnr = '127.0.0.1'
        user = self.user

        # Regular account without failed attempts logged.
        self.assertEqual(self.guard.lock_count(user), 0)
        self.assertEqual(self.guard.lock_time(user), 0)
        self.assertEqual(self.guard.release_time(user), 0)
        self.assertEqual(self.guard.user_locked(user), False)

        # Log failed attempt - this time with the real method.
        self.assertEqual(self.guard.failed_count(user, ipnr), 1)
        # Mock acct_mgr.LoginModule.authenticate behavior.
        if self.guard.user_locked(user):
            self.guard.lock_count(user, 'up')

        self.assertEqual(self.guard.lock_count(user), 1)
        self.assertEqual(self.guard.lock_time(user), 0)
        self.assertEqual(self.guard.release_time(user), 0)
        self.assertEqual(self.guard.user_locked(user), True)
        # Switch to time lock.
        self.env.config.set('account-manager', 'user_lock_time', 2)
        self.assertTrue(self.guard.release_time(user) > 0)
        self.assertEqual(self.guard.user_locked(user), True)
        sleep(2)
        self.assertEqual(self.guard.user_locked(user), False)

        self.assertEqual(self.guard.lock_time(user), 2)
        self.assertEqual(self.guard.lock_time(user, True), 2)
        self.env.config.set('account-manager', 'user_lock_time_progression',
                            3)
        self.assertEqual(self.guard.lock_time(user, True), 6)
        # Switch-back to permanent locking.
        self.env.config.set('account-manager', 'user_lock_time', 0)
        self.assertEqual(self.guard.user_locked(user), True)

    def test_lock_count(self):
        user = self.user
        self.assertEqual(self.guard.lock_count(user), 0)
        # Validate helper method too.
        self._mock_failed_attempt()
        # Increment per failed login.
        self.assertEqual(self.guard.lock_count(user, 'set'), 2)
        self.assertEqual(self.guard.lock_count(user), 2)
        # Return updated value on reset as well.
        self.assertEqual(self.guard.lock_count(user, 'reset'), 0)

    def test_lock_time(self):
        self.env.config.set('account-manager', 'user_lock_time', 30)
        self.env.config.set('account-manager', 'user_lock_time_progression',
                            1)

        # Won't track anonymous sessions and unknown accounts/users.
        self.assertEqual(self.guard.lock_time(None), 0)

        # Regular account without failed attempts logged.
        user = self.user
        self.assertEqual(self.guard.lock_time(user), 30)
        self._mock_failed_attempt(5)
        # Fixed lock time, no progression, with default configuration values.
        self.assertEqual(self.guard.lock_time(user), 30)

        # Preview calculation.
        self.assertEqual(self.guard.lock_time(user, True), 30)
        # Progression with base 3.
        self.env.config.set('account-manager', 'user_lock_time_progression',
                            3)
        self.assertEqual(self.guard.lock_time(user, True), 30 * 3 ** 5)
        self.env.config.set('account-manager', 'user_lock_max_time', 1800)
        self.assertEqual(self.guard.lock_time(user, True), 1800)

    def test_release_time(self):
        lock_time = 30
        self.env.config.set('account-manager', 'user_lock_time', lock_time)
        self.env.config.set('account-manager', 'user_lock_time_progression',
                            1)

        # Won't track anonymous sessions and unknown accounts/users.
        self.assertEqual(self.guard.release_time(None), None)

        # Regular account without failed attempts logged.
        user = self.user
        self.assertEqual(self.guard.release_time(user), None)
        # Account with failed attempts logged.
        release_ts = self._mock_failed_attempt() + lock_time
        self.assertEqual(self.guard.release_time(user), release_ts)
        release_ts = self._mock_failed_attempt() + lock_time
        self.assertEqual(self.guard.release_time(user), release_ts)

        # Permanently locked account.
        self.env.config.set('account-manager', 'user_lock_time', 0)
        self.assertEqual(self.guard.release_time(user), 0)

        # Result with locking disabled.
        self.env.config.set('account-manager', 'login_attempt_max_count', 0)
        self.env.config.set('account-manager', 'user_lock_time', 30)
        self.assertEqual(self.guard.release_time(user), None)

    def test_user_locked(self):
        # Won't track anonymous sessions and unknown accounts/users.
        for user in [None, 'anonymous']:
            self.assertEqual(self.guard.user_locked(user), None)
        # Regular account without failed attempts logged.
        user = self.user
        self.assertEqual(self.guard.user_locked(user), False)

        # Permanently locked account.
        self._mock_failed_attempt()
        self.assertEqual(self.guard.user_locked(user), True)
        # Result with locking disabled.
        self.env.config.set('account-manager', 'login_attempt_max_count', 0)
        self.assertEqual(self.guard.user_locked(user), None)


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(AccountGuardTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
