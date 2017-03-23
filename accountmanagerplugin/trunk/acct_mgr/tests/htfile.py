# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2011-2013 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

import os.path
import shutil
import tempfile
import unittest

from trac.test import EnvironmentStub

from acct_mgr.htfile import HtDigestStore, HtPasswdStore


class _BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.basedir = os.path.realpath(tempfile.mkdtemp())
        self.env = EnvironmentStub()
        self.env.path = os.path.join(self.basedir, 'trac-tempenv')
        os.mkdir(self.env.path)

    def tearDown(self):
        shutil.rmtree(self.basedir)

    # Helpers

    def _create_file(self, *path, **kw):
        filename = os.path.join(self.basedir, *path)
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        fd = file(filename, 'w')
        content = kw.get('content')
        if content is not None:
            fd.write(content)
        fd.close()
        return filename

    def _init_password_file(self, flavor, filename, content=''):
        filename = self._create_file(filename, content=content)
        self.env.config.set('account-manager', flavor + '_file', filename)

    def _do_password_test(self, flavor, filename, content):
        self._init_password_file(flavor, filename, content)
        self.assertTrue(self.store.check_password('user', 'password'))

    # Tests

    def test_overwrite(self):
        self._init_password_file(self.flavor, 'test_overwrite_%s'
                                 % self.flavor)
        self.assertTrue(self.store.set_password('user1', 'password1'))
        self.assertFalse(self.store.set_password('user1', 'password2',
                                                 overwrite=False))
        self.assertTrue(self.store.check_password('user1', 'password1'))
        self.assertTrue(self.store.set_password('user2', 'password',
                                                overwrite=False))

    def test_unicode(self):
        self.env.config.set('account-manager', 'htdigest_realm',
                            u'UnicodeRealm\u4e60')
        user = u'\u4e61'
        password = u'\u4e62'
        self._init_password_file(self.flavor, 'test_unicode_%s'
                                 % self.flavor)
        self.store.set_password(user, password)
        self.assertEqual(list(self.store.get_users()), [user])
        self.assertTrue(self.store.check_password(user, password))
        self.assertTrue(self.store.delete_user(user))
        self.assertEqual(list(self.store.get_users()), [])


class HtDigestTestCase(_BaseTestCase):
    flavor = 'htdigest'

    def setUp(self):
        _BaseTestCase.setUp(self)
        self.env.config.set('account-manager', 'htdigest_realm',
                            'TestRealm')
        self.store = HtDigestStore(self.env)

    def test_userline(self):
        self.assertEqual(self.store.userline('user', 'password'),
                         'user:TestRealm:752b304cc7cf011d69ee9b79e2cd0866')

    def test_file(self):
        self._do_password_test(
            self.flavor, 'test_file',
            'user:TestRealm:752b304cc7cf011d69ee9b79e2cd0866')

    def test_update_password(self):
        self._init_password_file(self.flavor, 'test_passwdupd')
        self.store.set_password('foo', 'pass1')
        self.assertFalse(self.store.check_password('foo', 'pass2'))
        self.store.set_password('foo', 'pass2')
        self.assertTrue(self.store.check_password('foo', 'pass2'))
        self.store.set_password('foo', 'pass3', 'pass2')
        self.assertTrue(self.store.check_password('foo', 'pass3'))


class HtPasswdTestCase(_BaseTestCase):
    flavor = 'htpasswd'

    def setUp(self):
        _BaseTestCase.setUp(self)
        self.store = HtPasswdStore(self.env)

    def test_md5(self):
        self._do_password_test(self.flavor, 'test_md5',
                               'user:$apr1$xW/09...$fb150dT95SoL1HwXtHS/I0\n')

    def test_crypt(self):
        self._do_password_test(self.flavor, 'test_crypt',
                               'user:QdQ/xnl2v877c\n')

    def test_sha(self):
        self._do_password_test(self.flavor, 'test_sha',
                               'user:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n')

    def test_sha256(self):
        try:
            self._do_password_test(self.flavor, 'test_sha256',
                                   'user:$5$rounds=535000$saltsaltsaltsalt$'
                                   'wfx3LZ09XA7qrZB.ttuCbBidMXt51Kgu5YQ.YFq'
                                   'zxA7\n')
        except NotImplementedError:
            pass

    def test_sha512(self):
        try:
            self._do_password_test(self.flavor, 'test_sha512',
                                   'user:$6$rounds=535000$saltsaltsaltsalt$'
                                   '9ExQK2S3YXW7/FlfUcw2vy7WF.NH5ZF6SIT14Dj'
                                   'ngOGkcx.5mINko67cLRrqFFh1AltOT4uPnET7Bs'
                                   'JXuI56H/\n')
        except NotImplementedError:
            pass

    def test_no_trailing_newline(self):
        self._do_password_test(self.flavor, 'test_no_trailing_newline',
                               'user:$apr1$xW/09...$fb150dT95SoL1HwXtHS/I0')

    def test_add_with_no_trailing_newline(self):
        filename = self._create_file(
            'test_add_with_no_trailing_newline',
            content='user:$apr1$xW/09...$fb150dT95SoL1HwXtHS/I0')
        self.env.config.set('account-manager', 'htpasswd_file', filename)
        self.assertTrue(self.store.check_password('user', 'password'))
        self.store.set_password('user2', 'password2')
        self.assertTrue(self.store.check_password('user', 'password'))
        self.assertTrue(self.store.check_password('user2', 'password2'))

    def test_update_password(self):
        self._init_password_file(self.flavor, 'test_passwdupd')
        self.store.set_password('foo', 'pass1')
        self.assertFalse(self.store.check_password('foo', 'pass2'))
        self.store.set_password('foo', 'pass2')
        self.assertTrue(self.store.check_password('foo', 'pass2'))
        self.store.set_password('foo', 'pass3', 'pass2')
        self.assertTrue(self.store.check_password('foo', 'pass3'))

    def test_create_hash(self):
        self._init_password_file(self.flavor, 'test_hash')
        self.env.config.set('account-manager', 'htpasswd_hash_type', 'bad')
        self.assertTrue(self.store.userline('user',
                                            'password').startswith('user:'))
        self.assertFalse(self.store.userline('user', 'password'
                                             ).startswith('user:$apr1$'))
        self.assertFalse(self.store.userline('user', 'password'
                                             ).startswith('user:{SHA}'))
        self.store.set_password('user', 'password')
        self.assertTrue(self.store.check_password('user', 'password'))
        self.env.config.set('account-manager', 'htpasswd_hash_type', 'md5')
        self.assertTrue(self.store.userline('user', 'password'
                                            ).startswith('user:$apr1$'))
        self.store.set_password('user', 'password')
        self.assertTrue(self.store.check_password('user', 'password'))
        self.env.config.set('account-manager', 'htpasswd_hash_type', 'sha')
        self.assertTrue(self.store.userline('user', 'password'
                                            ).startswith('user:{SHA}'))
        self.store.set_password('user', 'password')
        self.assertTrue(self.store.check_password('user', 'password'))
        self.env.config.set('account-manager', 'htpasswd_hash_type', 'sha256')
        try:
            self.assertTrue(self.store.userline('user', 'password'
                                                ).startswith('user:$5$'))
        except NotImplementedError:
            pass
        else:
            self.store.set_password('user', 'password')
            self.assertTrue(self.store.check_password('user', 'password'))
        self.env.config.set('account-manager', 'htpasswd_hash_type',
                            'sha512')
        try:
            self.assertTrue(self.store.userline('user', 'password'
                                                ).startswith('user:$6$'))
        except NotImplementedError:
            pass
        else:
            self.store.set_password('user', 'password')
            self.assertTrue(self.store.check_password('user', 'password'))


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(HtDigestTestCase))
    suite.addTest(unittest.makeSuite(HtPasswdTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
