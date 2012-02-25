#!/usr/bin/env python

# License: 
#   "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good

from setuptools import setup

extra = {}

try:
    from trac.util.dist  import  get_l10n_cmdclass
    cmdclass = get_l10n_cmdclass()
    if cmdclass:
        extra['cmdclass'] = cmdclass
        extractors = [
            ('**.py',                'python', None),
            ('**/templates/**.html', 'genshi', None),
        ]
        extra['message_extractors'] = {
            'acct_mgr': extractors,
        }
# i18n is implemented to be optional here
except ImportError:
    pass


setup(
    name = 'TracAccountManager',
    version = '0.4',
    author = 'Matthew Good',
    author_email = 'trac@matt-good.net',
    maintainer = 'Steffen Hoffmann',
    maintainer_email = 'hoff.st@web.de',
    url = 'http://trac-hacks.org/wiki/AccountManagerPlugin',
    description = 'User account management plugin for Trac',

    license = 'THE BEER-WARE LICENSE',

    packages=['acct_mgr'],
    package_data={
        'acct_mgr': [
            'htdocs/*', 'locale/*/LC_MESSAGES/*.mo', 'locale/.placeholder',
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
            'acct_mgr.svnserve = acct_mgr.svnserve',
            'acct_mgr.web_ui = acct_mgr.web_ui',
            'acct_mgr.notification = acct_mgr.notification',
        ]
    },
    **extra
)
