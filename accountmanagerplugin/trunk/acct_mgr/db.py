# -*- coding: utf-8 -*-
#
# Copyright (C) 2007 Matthew Good <trac@matt-good.net>
# Copyright (C) 2010-2012 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

from trac.config import ExtensionOption
from trac.core import Component, implements

from acct_mgr.api import IPasswordStore
from acct_mgr.pwhash import IPasswordHashMethod


class SessionStore(Component):
    implements(IPasswordStore)

    hash_method = ExtensionOption('account-manager', 'hash_method',
        IPasswordHashMethod, 'HtDigestHashMethod',
        doc="IPasswordHashMethod used to create new/updated passwords")

    def __init__(self):
        self.key = 'password'
        # Check for valid hash method configuration.
        self.hash_method_enabled

    def get_users(self):
        """Returns an iterable of the known usernames."""
        for sid, in self.env.db_query("""
               SELECT DISTINCT sid FROM session_attribute
               WHERE authenticated=1 AND name=%s
               """, (self.key,)):
            yield sid

    def has_user(self, user):
        for _ in self.env.db_query("""
                SELECT * FROM session_attribute
                WHERE authenticated=1 AND name=%s AND sid=%s
                """, (self.key, user)):
            return True
        return False

    def set_password(self, user, password, old_password=None, overwrite=True):
        """Sets the password for the user.

        This should create the user account, if it doesn't already exist.
        Returns True, if a new account was created, and False,
        if an existing account was updated.
        """
        if not self.hash_method_enabled:
            return
        hash_ = self.hash_method.generate_hash(user, password)
        with self.env.db_transaction as db:
            sql = "WHERE authenticated=1 AND name=%s AND sid=%s"
            if overwrite:
                db("""
                    UPDATE session_attribute SET value=%s
                    """ + sql, (hash_, self.key, user))
            exists = False
            for _ in db("""
                    SELECT value FROM session_attribute
                    """ + sql, (self.key, user)):
                exists = True
                break
            if not exists:
                db("""
                    INSERT INTO session_attribute
                     (sid,authenticated,name,value)
                    VALUES (%s,1,%s,%s)
                    """, (user, self.key, hash_))

        return not exists

    def check_password(self, user, password):
        """Checks if the password is valid for the user."""
        if not self.hash_method_enabled:
            return
        for hash_, in self.env.db_query("""
                SELECT value FROM session_attribute
                WHERE authenticated=1 AND name=%s AND sid=%s
                """, (self.key, user)):
            return self.hash_method.check_hash(user, password, hash_)
        # Return value 'None' allows to proceed with another, chained store.
        return

    def delete_user(self, user):
        """Deletes the user account.

        Returns True, if the account existed and was deleted, False otherwise.
        """
        with self.env.db_transaction as db:
            sql = "WHERE authenticated=1 AND name=%s AND sid=%s"
            # Avoid has_user() to make this transaction atomic.
            exists = False
            for _ in db("""
                    SELECT * FROM session_attribute %s
                    """ % sql, (self.key, user)):
                exists = True
                break
            if exists:
                db("""
                    DELETE FROM session_attribute %s
                    """ % sql, (self.key, user))

        return exists

    @property
    def hash_method_enabled(self):
        """Prevent AttributeError on plugin load.

        This would happen, if the implementation of 'IPasswordHashMethod'
        interface configured in 'hash_method' has not been enabled.
        """
        try:
            self.hash_method
        except AttributeError:
            self.log.error("%s: no IPasswordHashMethod enabled - fatal, "
                           "can't work", self.__class__)
            return
        return True
