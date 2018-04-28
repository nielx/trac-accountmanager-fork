#!/usr/bin/env python

# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

from setuptools import find_packages, setup

extra = {}

try:
    from trac.dist import get_l10n_cmdclass
    from trac.dist import extract_python
except ImportError:
    pass
else:
    cmdclass = get_l10n_cmdclass()
    if cmdclass:
        extra['cmdclass'] = cmdclass
        extractors = [
            ('**/templates/**.html', 'genshi', None),
            ('**.py', 'trac.dist:extract_python', None),
        ]
        extra['message_extractors'] = {
            'acct_mgr': extractors,
        }

setup(
    name='TracAccountManager',
    version='0.5.1',
    author='Matthew Good',
    author_email='trac@matt-good.net',
    maintainer='Steffen Hoffmann',
    maintainer_email='hoff.st@web.de',
    url='https://trac-hacks.org/wiki/AccountManagerPlugin',
    description='User account management plugin for Trac',
    license='3-Clause BSD',
    packages=find_packages(exclude=['*.tests*']),
    package_data={
        'acct_mgr': [
            'htdocs/*.css', 'htdocs/js/*', 'htdocs/*.png',
            'locale/*/LC_MESSAGES/*.mo', 'locale/.placeholder',
            'templates/*.html', 'templates/*.txt'
        ]
    },
    test_suite='acct_mgr.tests.test_suite',
    zip_safe=True,
    install_requires=['Trac'],
    extras_require={
        'Babel': 'Babel>= 0.9.5',
        'Trac': 'Trac >= 0.12',
        'announcer': 'TracAnnouncer',
        'forms': 'TracForms',
        'pyrad': 'Pyrad',
        'screenshots': 'TracScreenshots',
        'vote': 'TracVote',
    },
    entry_points={
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
            'acct_mgr.opt.announcer.uid_chg = '
            'acct_mgr.opt.announcer.uid_chg[announcer]',
            'acct_mgr.opt.tracforms.uid_chg = '
            'acct_mgr.opt.tracforms.uid_chg[forms]',
            'acct_mgr.opt.radius = acct_mgr.opt.radius[pyrad]',
            'acct_mgr.opt.tracscreenshots.uid_chg = '
            'acct_mgr.opt.tracscreenshots.uid_chg[screenshots]',
            'acct_mgr.opt.tracvote.uid_chg = '
            'acct_mgr.opt.tracvote.uid_chg[vote]',
        ]
    },
    **extra
)
