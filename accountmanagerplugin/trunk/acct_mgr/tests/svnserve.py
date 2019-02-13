# -*- coding: utf-8 -*-
"""
Test suite for SvnServePasswordStore.
"""

import os.path
import tempfile
import unittest

from acct_mgr.svnserve import SvnServePasswordStore

from trac.test import EnvironmentStub, rmtree


class SvnServePasswordTestCase(unittest.TestCase):
    """Test cases for SvnServePasswordStore.
    """

    def setUp(self):
        env_path = os.path.realpath(tempfile.mkdtemp(prefix='trac-testdir-'))
        self.env = EnvironmentStub(path=env_path)
        self.store = SvnServePasswordStore(self.env)
        self.default_content = [
            '[users]\n',
            'spam = eggs\n',
            'knights = ni\n',
        ]

    def tearDown(self):
        self.env.shutdown()
        rmtree(self.env.path)

    def _create_file(self, test_id, extra_content=None):
        file_name = os.path.join(self.env.path, 'test_' + test_id)
        with open(file_name, 'w') as f:
            f.writelines(self.default_content)
            if extra_content is not None:
                f.writelines(extra_content)
        self.env.config.set('account-manager', 'password_file', file_name)

    def test_check_password_ok(self):
        """Verify check_password success: correct user and password.
        """
        self._create_file(test_id='check_password_ok')
        self.assertTrue(self.store.check_password('knights', 'ni'))

    def test_check_password_bad(self):
        """Verify check_password failure: correct user, incorrect
        password.
        """
        self._create_file(test_id='check_password_bad')
        self.assertFalse(self.store.check_password('knights', 'noo'))

    def test_check_password_unknown(self):
        """Verify check_password failure: unknown user."""
        self._create_file(test_id='check_password_unknown')
        self.assertIsNone(self.store.check_password('brian', 'naughty'))

    def test_delete_user_ok(self):
        """Verify delete_user success."""
        self._create_file(test_id='delete_user_ok')
        user_to_delete = 'knights'
        self.assertTrue(self.store.delete_user(user_to_delete))
        self.assertFalse(self.store.has_user(user_to_delete))

    def test_delete_user_unknown(self):
        """Verify delete_user failure: unknown user."""
        self._create_file(test_id='delete_user_unknown')
        user_to_delete = 'brian'
        self.assertFalse(self.store.delete_user(user_to_delete))

    def test_get_users(self):
        self._create_file(test_id='get_users')
        self.assertEqual(
            self.store.get_users(),
            ['spam', 'knights'],
        )

    def test_has_user_ok(self):
        """Verify has_user for an existing user."""
        self._create_file(test_id='has_user_ok')
        self.assertTrue(self.store.has_user('knights'))

    def test_has_user_unknown(self):
        """Verify has_user for an unknown user."""
        self._create_file(test_id='has_user_unknown')
        self.assertFalse(self.store.has_user('brian'))

    def test_set_password(self):
        """Verify set_password for a new user."""
        self._create_file(test_id='set_password')
        new_user = 'brian'
        new_passwd = 'naughty'
        self.assertFalse(self.store.has_user(new_user))
        self.assertTrue(self.store.set_password(new_user, new_passwd))
        self.assertTrue(self.store.check_password(new_user, new_passwd))

    def test_update_password(self):
        """Verify set_password for an existing user."""
        self._create_file(test_id='update_password')
        existing_user = 'knights'
        new_passwd = 'noo'
        self.assertTrue(self.store.has_user(existing_user))
        self.assertFalse(self.store.set_password(existing_user, new_passwd))
        self.assertTrue(self.store.check_password(existing_user, new_passwd))

    def test_overwrite_password(self):
        """Verify set_password rejects overwrite when instructed."""
        self._create_file(test_id='update_password')
        existing_user = 'knights'
        new_passwd = 'noo'
        self.assertTrue(self.store.has_user(existing_user))
        self.assertFalse(self.store.set_password(existing_user, new_passwd,
                                                 overwrite=False))
        self.assertFalse(self.store.check_password(existing_user, new_passwd))


def test_suite():
    """
    The assembled test suite.
    """
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(SvnServePasswordTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
