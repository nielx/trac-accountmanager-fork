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
import time
import unittest

from Cookie  import SimpleCookie as Cookie

from trac.test  import EnvironmentStub, Mock
from trac.web.session  import Session

from acct_mgr.model  import delete_user, email_associated, email_verified, \
                            del_user_attribute, get_user_attribute, \
                            set_user_attribute, last_seen, user_known, \
                            prime_auth_session


class ModelTestCase(unittest.TestCase):

    def setUp(self):
        self.env = EnvironmentStub(default_data=True, enable=['trac.*'])
        self.env.path = tempfile.mkdtemp()
        self.db = self.env.get_db_cnx()

    def tearDown(self):
        self.db.close()
        # Really close db connections.
        self.env.shutdown()
        shutil.rmtree(self.env.path)

    # Helpers

    def _create_session(self, user, authenticated=1, name='', email=''):
        args = dict(username=user, name=name, email=email)
        incookie = Cookie()
        incookie['trac_session'] = '123456'
        self.req = Mock(authname=bool(authenticated) and user or 'anonymous',
                        args=args, base_path='/',
                        chrome=dict(warnings=list()),
                        href=Mock(prefs=lambda x: None),
                        incookie=incookie, outcookie=Cookie(),
                        redirect=lambda x: None)
        self.req.session = Session(self.env, self.req)
        self.req.session.save()

    def test_last_seen(self):
        user = 'user'

        # Use basic function.
        self.assertEqual(last_seen(self.env), [])
        self._create_session(user)
        # Devel: Not fail-safe, will produce random false-negatives.
        now = time.time()
        self.assertEqual(last_seen(self.env), [(user, int(now))])

        # Use 1st optional kwarg.
        self.assertEqual(last_seen(self.env, user), [(user, int(now))])
        user = 'anotheruser'
        self.assertEqual(last_seen(self.env, user), [])
        # Don't care for anonymous session IDs.
        self._create_session(user, False)
        self.assertEqual(last_seen(self.env, user), [])

    def test_user_known(self):
        user = 'user'
        self.assertFalse(user_known(self.env, user))
        # Don't care for anonymous session IDs.
        self._create_session(user, False)
        self.assertFalse(user_known(self.env, user))
        self._create_session(user)
        self.assertTrue(user_known(self.env, user))

    def test_get_user_attribute(self):
        self.assertEqual(get_user_attribute(self.env, authenticated=None), {})
        cursor = self.db.cursor()
        cursor.executemany("""
            INSERT INTO session_attribute
                   (sid,authenticated,name,value)
            VALUES (%s,%s,%s,%s)
        """, [
        ('user', 0, 'attribute1', 'value1'),
        ('user', 0, 'attribute2', 'value2'),
        ('user', 1, 'attribute1', 'value1'),
        ('user', 1, 'attribute2', 'value2'),
        ('another', 1, 'attribute2', 'value3')]
        )
        no_constraints = get_user_attribute(self.env, authenticated=None)
        # Distinct session IDs form top-level keys.
        self.assertEqual(set(no_constraints.keys()),
                         set([u'user', u'another']))
        # There are probably anonymous sessions named equally to
        # authenticated ones, causing different nested dicts below each
        # session ID.  Btw, only authenticated ones are real usernames.
        self.assertTrue(0 in no_constraints['user'])
        self.assertTrue(1 in no_constraints['user'])
        self.assertFalse(0 in no_constraints['another'])
        self.assertTrue(1 in no_constraints['another'])
        # Touch some of the attributes stored before.
        self.assertTrue(no_constraints['user'][0]['attribute1'], 'value1')
        self.assertTrue(no_constraints['user'][1]['attribute2'], 'value2')
        self.assertEqual(no_constraints['another'].get(0), None)
        self.assertTrue(no_constraints['another'][1]['attribute2'], 'value3')

    def test_set_user_attribute(self):
        set_user_attribute(self.env, 'user', 'attribute1', 'value1')
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT name,value
            FROM   session_attribute
            WHERE  sid='user'
            AND    authenticated=1
        """)
        self.assertEqual(cursor.fetchall(), [('attribute1', 'value1')])
        # Setting an attribute twice will eventually just update the value.
        set_user_attribute(self.env, 'user', 'attribute1', 'value2')
        cursor.execute("""
            SELECT name,value
            FROM   session_attribute
            WHERE  sid='user'
            AND    authenticated=1
        """)
        self.assertEqual(cursor.fetchall(), [('attribute1', 'value2')])
        # All values are stored as strings internally, but the function
        # should take care to handle forseeable abuse gracefully.
        # This is a test for possible regressions of #10772.
        set_user_attribute(self.env, 'user', 'attribute1', 0)
        cursor.execute("""
            SELECT name,value
            FROM   session_attribute
            WHERE  sid='user'
            AND    authenticated=1
        """)
        self.assertEqual(cursor.fetchall(), [('attribute1', '0')])


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ModelTestCase, 'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
