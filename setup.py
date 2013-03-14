#!/usr/bin/env python

# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

from setuptools import setup

extra = {}

has_trac_extract_python = False
try:
    from trac.util.dist import get_l10n_cmdclass
    try:
        from trac.dist import get_l10n_trac_cmdclass
        cmdclass = get_l10n_trac_cmdclass()
        has_trac_extract_python = True
    except ImportError:
        # Trac < 1.0, using other compatibility code here.
        cmdclass = get_l10n_cmdclass()
    if cmdclass:
        extra['cmdclass'] = cmdclass
        extractors = [
            ('**/templates/**.html', 'genshi', None),
        ]
        if has_trac_extract_python:
            extractors.append(
                ('**.py', 'trac.dist:extract_python', None))
        else:
            extractors.append(
                ('**.py', 'acct_mgr.compat:extract_python', None))
        extra['message_extractors'] = {
            'acct_mgr': extractors,
        }
# Trac < 0.12, i18n is implemented to be optional here.
except ImportError:
    pass


setup(
    name = 'TracAccountManager',
    version = '0.5',
    author = 'Matthew Good',
    author_email = 'trac@matt-good.net',
    maintainer = 'Steffen Hoffmann',
    maintainer_email = 'hoff.st@web.de',
    url = 'http://trac-hacks.org/wiki/AccountManagerPlugin',
    description = 'User account management plugin for Trac',

    license = 'BSD',

    packages=['acct_mgr'],
    package_data={
        'acct_mgr': [
            'htdocs/*.css', 'htdocs/js/*', 'htdocs/*.png',
            'locale/*/LC_MESSAGES/*.mo', 'locale/.placeholder',
            'templates/*.html', 'templates/*.txt'
        ]
    },
    test_suite = 'acct_mgr.tests.suite',
    zip_safe=True,
    install_requires = ['Genshi >= 0.5', 'Trac >= 0.11'],
    extras_require = {'Babel': 'Babel>= 0.9.5', 'Trac': 'Trac >= 0.12'},
    entry_points = {
        'trac.plugins': [
            'acct_mgr.admin = acct_mgr.admin',
            'acct_mgr.api = acct_mgr.api',
            'acct_mgr.db = acct_mgr.db',
            'acct_mgr.macros = acct_mgr.macros',
            'acct_mgr.htfile = acct_mgr.htfile',
            'acct_mgr.http = acct_mgr.http',
            'acct_mgr.pwhash = acct_mgr.pwhash',
            'acct_mgr.register = acct_mgr.register',
            'acct_mgr.svnserve = acct_mgr.svnserve',
            'acct_mgr.web_ui = acct_mgr.web_ui',
            'acct_mgr.notification = acct_mgr.notification',
        ]
    },
    **extra
)
