# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

import os

from acct_mgr.api import IPasswordStore
from acct_mgr.util import EnvRelativePathOption
from trac.config import Configuration
from trac.core import Component, implements
from trac.versioncontrol.api import RepositoryManager
from trac.versioncontrol.cache import CachedRepository


class SvnServePasswordStore(Component):
    """PasswordStore implementation for reading svnserve's password file format
    """

    implements(IPasswordStore)

    filename = EnvRelativePathOption('account-manager', 'password_file',
        doc="""Path to the users file; leave blank to locate the users file
        by reading svnserve.conf from the default repository.
        """)

    _userconf = None

    @property
    def _config(self):
        filename = self.filename or self._get_password_file()
        if self._userconf is None or filename != self._userconf.filename:
            self._userconf = Configuration(filename)
            # Overwrite default with str class to preserve case.
            self._userconf.parser.optionxform = str
            self._userconf.parse_if_needed(force=True)
        else:
            self._userconf.parse_if_needed()
        return self._userconf

    def _get_password_file(self):
        repos = RepositoryManager(self.env).get_repository('')
        if not repos:
            return None
        if isinstance(repos, CachedRepository):
            repos = repos.repos
        if repos.params['type'] in ('svn', 'svnfs', 'direct-svnfs'):
            conf = Configuration(os.path.join(repos.path, 'conf',
                                              'svnserve.conf'))
            return conf['general'].getpath('password-db')

    # IPasswordStore methods

    def get_users(self):
        return [user for (user, password) in self._config.options('users')]

    def has_user(self, user):
        return user in self._config['users']

    def set_password(self, user, password, old_password=None):
        cfg = self._config
        cfg.set('users', user, password)
        cfg.save()

    def check_password(self, user, password):
        if self.has_user(user):
            return password == self._config.get('users', user)
        return None

    def delete_user(self, user):
        cfg = self._config
        cfg.remove('users', user)
        cfg.save()
