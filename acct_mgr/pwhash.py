# -*- coding: utf-8 -*-
#
# Copyright (C) 2007 Matthew Good <trac@matt-good.net>
# Copyright (C) 2011 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

import hashlib
import re
from base64 import b64encode
from binascii import hexlify
from os import urandom

from acct_mgr.api import _
from acct_mgr.md5crypt import md5crypt
from trac.config import Option
from trac.core import Component, Interface, implements

try:
    from passlib.apps import custom_app_context as passlib_ctxt
except ImportError:
    # not available
    # Hint: Python2.5 is required too
    passlib_ctxt = None


class IPasswordHashMethod(Interface):
    def generate_hash(user: str, password: str) -> str:
        pass

    def check_hash(user: str, password: str, hash: str) -> bool:
        pass


class HtPasswdHashMethod(Component):
    implements(IPasswordHashMethod)

    hash_type = Option('account-manager', 'db_htpasswd_hash_type', 'crypt',
        doc="Default hash type of new/updated passwords")

    def generate_hash(self, user: str, password: str) -> str:
        password = password.encode("utf-8")
        return mkhtpasswd(password, self.hash_type)

    def check_hash(self, user: str, password: str, hash: str) -> bool:
        password = bytes(password, "utf-8")
        hash2 = htpasswd(password, bytes(hash, "utf-8"))
        return hash == hash2


class HtDigestHashMethod(Component):
    implements(IPasswordHashMethod)

    realm = Option('account-manager', 'db_htdigest_realm', '',
        doc="Realm to select relevant htdigest db entries")

    def generate_hash(self, user: str, password: str) -> str:
        user, password, realm = _encode(user, password, self.realm)
        return ':'.join([self.realm, htdigest(user, realm, password)])

    def check_hash(self, user: str, password: str, hash: str) -> bool:
        return hash == self.generate_hash(user, password)


def _encode(*args) -> [bytes]:
    return [a.encode('utf-8') for a in args]


# check for the availability of the "crypt" module for checking passwords on
# Unix-like platforms
# MD5 is still used when adding/updating passwords with htdigest
try:
    from crypt import crypt
except ImportError:
    crypt = None


def salt(salt_char_count=8) -> bytes:
    s = bytearray()
    v = int(hexlify(urandom(int(salt_char_count / 8 * 6))), 16)
    itoa64 = b'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    for i in range(int(salt_char_count)):
        s.append(itoa64[v & 0x3f])
        v >>= 6
    return s


def hash_prefix(hash_type: str) -> bytes:
    """Map hash type to salt prefix."""
    if hash_type == 'md5':
        return b'$apr1$'
    elif hash_type == 'sha':
        return b'{SHA}'
    elif hash_type == 'sha256':
        return b'$5$'
    elif hash_type == 'sha512':
        return b'$6$'
    else:
        # use 'crypt' hash by default anyway
        return b''


def htpasswd(password: bytes, hash: bytes) -> str:
    def from_hash(hash: bytes) -> (int, bytes):
        match = re.match(rb'\$[5,6]\$(?:rounds=(\d+)\$)?(\w+)', hash)
        groups = match.groups()
        rounds = int(groups[0]) if groups[0] is not None else 5000
        salt = groups[1]
        return rounds, salt

    if hash.startswith(b'$apr1$'):
        return str(md5crypt(password, hash[6:].split(b'$')[0], b'$apr1$'), "utf-8")
    elif hash.startswith(b'{SHA}'):
        return '{SHA}' + b64encode(hashlib.sha1(password).digest()).decode()
    elif passlib_ctxt is not None and hash.startswith(b'$5$') and \
                    'sha256_crypt' in passlib_ctxt.policy.schemes():
        rounds, salt = from_hash(hash)
        return passlib_ctxt.encrypt(password, scheme='sha256_crypt',
                                    rounds=rounds, salt=salt)
    elif passlib_ctxt is not None and hash.startswith(b'$6$') and \
                    'sha512_crypt' in passlib_ctxt.policy.schemes():
        rounds, salt = from_hash(hash)
        return passlib_ctxt.encrypt(password, scheme='sha512_crypt',
                                    rounds=rounds, salt=salt)
    elif crypt is None:
        # crypt passwords are only supported on Unix-like systems
        raise NotImplementedError(_("The \"crypt\" module is unavailable "
                                    "on this platform."))
    else:
        if hash.startswith(b'$5$') or hash.startswith(b'$6$'):
            # Import of passlib failed, now check, if crypt is capable.
            if not crypt(str(password, "utf8"), str(hash, "utf8")).startswith(str(hash, "utf8")):
                # No, so bail out.
                raise NotImplementedError(_(
                    """Neither are \"sha2\" hash algorithms supported by the
                    \"crypt\" module on this platform nor is \"passlib\"
                    available."""))
        return crypt(str(password, "utf-8"), str(hash, "utf-8"))


def mkhtpasswd(password: bytes, hash_type: str = '') -> str:
    hash_prefix_ = hash_prefix(hash_type)
    if hash_type.startswith('sha') and len(hash_type) > 3:
        salt_ = salt(16)
    else:
        # Don't waste entropy to older hash types.
        salt_ = salt()
    if hash_prefix_ == '':
        if crypt is None:
            salt_ = b'$apr1$' + salt_
    else:
        salt_ = hash_prefix_ + salt_
    return htpasswd(password, salt_)


def htdigest(user: bytes, realm: bytes, password: bytes) -> str:
    p = b':'.join([user, realm, password])
    return hashlib.md5(p).hexdigest()
