#!/usr/bin/env python
#
# Copyright (C) 2007 Matthew Good <trac@matt-good.net>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

import os
import sys

from trac.env import Environment

from acct_mgr.api import AccountManager
from acct_mgr.htfile import HtPasswdStore, HtDigestStore

env = Environment(sys.argv[1])

store = AccountManager(env).password_store
if isinstance(store, HtPasswdStore):
    env.config.set('account-manager', 'hash_method', 'HtPasswdHashMethod')
    prefix = ''
elif isinstance(store, HtDigestStore):
    env.config.set('account-manager', 'hash_method', 'HtDigestHashMethod')
    prefix = store.realm + ':'
else:
    print >> sys.stderr, 'Unsupported password store:', \
             store.__class__.__name__
    sys.exit(1)

password_file = os.path.join(env.path, env.config.get('account-manager',
                                                      'password_file'))
with open(password_file) as f:
    hashes = [line.strip().split(':', 1) for line in f]

hashes = [(u, p) for u, p in hashes if p.startswith(prefix)]

if hashes:
    with env.db_transaction as db:
        db.executemany("""
            INSERT INTO session_attribute (sid,authenticated,name,value)
            VALUES (%s,1,'password',%s)
            """, hashes)

env.config.set('account-manager', 'password_store', 'SessionStore')
env.config.save()
