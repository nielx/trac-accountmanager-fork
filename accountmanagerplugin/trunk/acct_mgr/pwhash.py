# -*- coding: utf8 -*-
#
# Copyright (C) 2007 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

from binascii import hexlify
from os import urandom

from trac.core import *
from trac.config import Option

from acct_mgr.api import AccountManager, _
from acct_mgr.hashlib_compat import md5, sha1
from acct_mgr.md5crypt import md5crypt


class IPasswordHashMethod(Interface):
    def generate_hash(user, password):
        pass

    def check_hash(user, password, hash):
        pass


class HtPasswdHashMethod(Component):
    implements(IPasswordHashMethod)

    hash_type = Option('account-manager', 'htpasswd_hash_type', 'crypt',
        doc = "Default hash type of new/updated passwords")

    def generate_hash(self, user, password):
        password = password.encode('utf-8')
        return mkhtpasswd(password, self.hash_type)

    def check_hash(self, user, password, hash):
        password = password.encode('utf-8')
        hash2 = htpasswd(password, hash)
        return hash == hash2


class HtDigestHashMethod(Component):
    implements(IPasswordHashMethod)

    realm = Option('account-manager', 'htdigest_realm', '',
        doc = "Realm to select relevant htdigest file entries")

    def generate_hash(self, user, password):
        user,password,realm = _encode(user, password, self.realm)
        return ':'.join([realm, htdigest(user, realm, password)])

    def check_hash(self, user, password, hash):
        return hash == self.generate_hash(user, password)


def _encode(*args):
    return [a.encode('utf-8') for a in args]

# check for the availability of the "crypt" module for checking passwords on
# Unix-like platforms
# MD5 is still used when adding/updating passwords
try:
    from crypt import crypt
except ImportError:
    crypt = None

def salt():
    s = ''
    v = long(hexlify(urandom(6)), 16)
    itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    for i in range(8):
        s += itoa64[v & 0x3f]; v >>= 6
    return s

def hash_prefix(hash_type):
    """Map hash type to salt prefix."""
    if hash_type == 'md5':
        return '$apr1$'
    elif hash_type == 'sha':
        return '{SHA}'
    else:
        # use 'crypt' hash by default anyway
        return ''

def htpasswd(password, hash):
    if hash.startswith('$apr1$'):
        return md5crypt(password, hash[6:].split('$')[0], '$apr1$')
    elif hash.startswith('{SHA}'):
        return '{SHA}' + sha1(password).digest().encode('base64')[:-1]
    elif crypt is None:
        # crypt passwords are only supported on Unix-like systems
        raise NotImplementedError(_("""The \"crypt\" module is unavailable
                                    on this platform."""))
    else:
        return crypt(password, hash)

def mkhtpasswd(password, hash_type=''):
    hash_prefix_ = hash_prefix(hash_type)
    salt_ = salt()
    if hash_prefix_ == '':
        if crypt is None:
            salt_ = '$apr1$' + salt_
    else:
        salt_ = hash_prefix_ + salt_
    return htpasswd(password, salt_)

def htdigest(user, realm, password):
    p = ':'.join([user, realm, password])
    return md5(p).hexdigest()
