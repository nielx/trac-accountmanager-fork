# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

import unittest
from datetime import datetime

from acct_mgr.util import pretty_precise_timedelta, remove_zwsp


class UtilTestCase(unittest.TestCase):
    def test_pretty_precise_timedelta(self):
        yesterday = datetime(2012, 12, 14)
        today = datetime(2012, 12, 15)
        tomorrow = datetime(2012, 12, 16)

        # Trac core compatible signature usage.
        self.assertEqual(pretty_precise_timedelta(None), '')
        self.assertEqual(pretty_precise_timedelta(None, None), '')
        self.assertEqual(pretty_precise_timedelta(today, today), '')
        self.assertEqual(pretty_precise_timedelta(today, tomorrow), '1 day')
        self.assertEqual(pretty_precise_timedelta(today, yesterday), '1 day')
        self.assertEqual(pretty_precise_timedelta(tomorrow, yesterday),
                         '2 days')

        # Alternative `diff` keyword argument usage.
        self.assertEqual(pretty_precise_timedelta(None, diff=0), '')
        # Use ngettext with default locale (English).
        self.assertEqual(pretty_precise_timedelta(None, diff=1), '1 second')
        self.assertEqual(pretty_precise_timedelta(None, diff=2), '2 seconds')
        # Limit resolution.
        self.assertEqual(pretty_precise_timedelta(None, diff=3, resolution=4),
                         'less than 4 seconds')
        self.assertEqual(pretty_precise_timedelta(None, diff=86399),
                         '23:59:59')
        self.assertEqual(pretty_precise_timedelta(None, diff=86400),
                         '1 day')
        self.assertEqual(pretty_precise_timedelta(None, diff=86401),
                         '1 day 1 second')

    def test_remove_zwsp(self):
        self.assertEqual(u'user', remove_zwsp(u'user'))
        self.assertEqual(u'user', remove_zwsp(u'\u200buser\u200b'))
        self.assertEqual(u'user', remove_zwsp(u'\u200fu\ufe00ser\u061c'))
        self.assertEqual(u'u\U000e00ffser', remove_zwsp(u'u\U000e00ffser'))
        self.assertEqual(u'user', remove_zwsp(u'u\U000e0100ser'))
        self.assertEqual(u'user', remove_zwsp(u'u\U000e01efser'))
        self.assertEqual(u'u\U000e01f0ser', remove_zwsp(u'u\U000e01f0ser'))


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(UtilTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
